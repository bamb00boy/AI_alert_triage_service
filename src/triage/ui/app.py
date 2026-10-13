"""approval-ui: FastAPI + HTMX, Keycloak (OIDC) login. Analysts approve/edit/reject; viewers read."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.middleware.sessions import SessionMiddleware

from triage.attack import load_catalog
from triage.config import Settings, get_settings
from triage.db import create_pool
from triage.schemas import ACTIONS
from triage.telemetry import current_trace_id, setup_telemetry, shutdown_telemetry

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")  # autoescaping on: alert data is untrusted
templates.env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)

STATUSES = ("pending_approval", "auto_closed", "approved", "rejected")
VERDICTS = ("malicious", "suspicious", "benign")


def current_user(request: Request) -> dict[str, Any]:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401)
    return user


def require_analyst(request: Request, user: dict = Depends(current_user)) -> dict[str, Any]:
    if request.app.state.settings.analyst_role not in user["roles"]:
        raise HTTPException(status_code=403, detail="analyst role required")
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await create_pool(app.state.settings.database_url, max_size=5)
    yield
    await app.state.pool.close()
    shutdown_telemetry()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_telemetry("approval-ui", settings.otlp_endpoint, settings.log_level)
    app = FastAPI(title="triage approval-ui", lifespan=lifespan)
    app.state.settings = settings
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret.get_secret_value(),
                       same_site="lax", https_only=False, session_cookie="triage_session")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,static")
    catalog = load_catalog(str(settings.attack_techniques_file))

    oauth = OAuth()
    oauth.register(
        name="keycloak",
        server_metadata_url=settings.oidc_discovery_url,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )

    @app.exception_handler(401)
    async def to_login(request: Request, exc: HTTPException):
        return RedirectResponse("/login", status_code=303)

    # --- auth -------------------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login")
    async def login(request: Request):
        return await oauth.keycloak.authorize_redirect(request, f"{settings.ui_base_url}/auth/callback")

    @app.get("/auth/callback")
    async def callback(request: Request):
        token = await oauth.keycloak.authorize_access_token(request)
        claims = token["userinfo"]  # validated ID token claims
        request.session["user"] = {
            "sub": claims["sub"],
            "username": claims.get("preferred_username", claims["sub"]),
            "roles": [r for r in claims.get("roles", []) if r in (settings.analyst_role, settings.viewer_role)],
        }
        request.session["id_token"] = token.get("id_token")
        return RedirectResponse("/", status_code=303)

    @app.get("/logout")
    async def logout(request: Request):
        id_token = request.session.pop("id_token", None)
        request.session.clear()
        metadata = await oauth.keycloak.load_server_metadata()
        query = {"client_id": settings.oidc_client_id, "post_logout_redirect_uri": f"{settings.ui_base_url}/"}
        if id_token:
            query["id_token_hint"] = id_token
        return RedirectResponse(f"{metadata['end_session_endpoint']}?{urlencode(query)}", status_code=303)

    # --- pages ------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def cases(request: Request, status: str = "pending_approval", user: dict = Depends(current_user)):
        where, args = ("", []) if status == "all" else ("WHERE status = $1", [status])
        rows = await request.app.state.pool.fetch(
            f"""SELECT case_id, created_at, status, rule_title, severity, verdict, technique_id, confidence,
                       recommended_action, gate_reasons, provider
                FROM cases {where} ORDER BY created_at DESC LIMIT 200""",  # noqa: S608 (where is a constant)
            *args,
        )
        counts = dict(await request.app.state.pool.fetch("SELECT status, count(*) FROM cases GROUP BY 1"))
        return templates.TemplateResponse(request, "cases.html", {
            "user": user, "rows": rows, "status": status, "statuses": STATUSES, "counts": counts,
        })

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    async def case_detail(request: Request, case_id: int, user: dict = Depends(current_user)):
        return templates.TemplateResponse(request, "case.html", await _case_context(request, case_id, user))

    # --- decisions (analyst only) -----------------------------------------------------

    @app.post("/cases/{case_id}/approve", response_class=HTMLResponse)
    async def approve(request: Request, case_id: int, comment: str = Form(""), user: dict = Depends(require_analyst)):
        case = await _load_pending(request, case_id)
        await _decide(request, case, user, "approved", case["decision"], comment)
        return await _panel(request, case_id, user)

    @app.post("/cases/{case_id}/reject", response_class=HTMLResponse)
    async def reject(request: Request, case_id: int, comment: str = Form(""), user: dict = Depends(require_analyst)):
        case = await _load_pending(request, case_id)
        await _decide(request, case, user, "rejected", None, comment)
        return await _panel(request, case_id, user)

    @app.post("/cases/{case_id}/edit", response_class=HTMLResponse)
    async def edit(
        request: Request,
        case_id: int,
        verdict: str = Form(...),
        technique_id: str = Form(...),
        recommended_action: str = Form(...),
        comment: str = Form(""),
        user: dict = Depends(require_analyst),
    ):
        case = await _load_pending(request, case_id)
        technique_id = technique_id.strip().upper() if technique_id.strip().lower() != "none" else "none"
        if verdict not in VERDICTS or recommended_action not in ACTIONS:
            raise HTTPException(422, "verdict/action must come from the allow-list")
        if technique_id != "none" and technique_id not in catalog.techniques:
            raise HTTPException(422, f"{technique_id} is not an ATT&CK technique")
        edited = dict(case["decision"] or {}) | {
            "verdict": verdict, "technique_id": technique_id, "recommended_action": recommended_action,
            "tactics": list(catalog.tactics_for(technique_id)),
        }
        await _decide(request, case, user, "approved", edited, comment, edited_by_analyst=True)
        return await _panel(request, case_id, user)

    return app


async def _case_context(request: Request, case_id: int, user: dict) -> dict[str, Any]:
    pool = request.app.state.pool
    case = await pool.fetchrow("SELECT * FROM cases WHERE case_id = $1", case_id)
    if case is None:
        raise HTTPException(404)
    alert = await pool.fetchval("SELECT alert FROM alerts WHERE alert_id = $1", case["alert_id"])
    audit = await pool.fetch(
        """SELECT seq, ts, actor, event_type, payload FROM audit_log
           WHERE (entity_type = 'case' AND entity_id = $1) OR (entity_type = 'alert' AND entity_id = $2)
           ORDER BY seq""",
        str(case_id), case["alert_id"],
    )
    return {
        "user": user, "case": case, "alert": alert, "audit": audit, "actions": ACTIONS, "verdicts": VERDICTS,
        "is_analyst": request.app.state.settings.analyst_role in user["roles"],
    }


async def _panel(request: Request, case_id: int, user: dict) -> HTMLResponse:
    return templates.TemplateResponse(request, "_decision_panel.html", await _case_context(request, case_id, user))


async def _load_pending(request: Request, case_id: int):
    case = await request.app.state.pool.fetchrow("SELECT * FROM cases WHERE case_id = $1", case_id)
    if case is None:
        raise HTTPException(404)
    if case["status"] != "pending_approval":
        raise HTTPException(409, f"case is already {case['status']}")
    return case


async def _decide(request: Request, case, user: dict, status: str, final: dict | None, comment: str,
                  *, edited_by_analyst: bool = False) -> None:
    async with request.app.state.pool.acquire() as conn, conn.transaction():
        updated = await conn.execute(
            """UPDATE cases SET status = $2, final_decision = $3, decided_by = $4, decided_at = now(),
                                updated_at = now()
               WHERE case_id = $1 AND status = 'pending_approval'""",
            case["case_id"], status, final, user["username"],
        )
        if not updated.endswith(" 1"):
            raise HTTPException(409, "case was decided concurrently")
        event = "case.edited" if edited_by_analyst else f"case.{status}"
        await conn.execute(
            "SELECT audit_append($1, $2, 'case', $3, $4, $5)",
            f"user:{user['username']}", event, str(case["case_id"]),
            {"before": case["decision"], "after": final, "comment": comment[:2000], "roles": user["roles"]},
            current_trace_id(),
        )
