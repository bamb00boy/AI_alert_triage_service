"""HMAC-SHA256 webhook signatures.

Signed string: ``f"{timestamp}.".encode() + raw_body``.
Headers:       ``X-Triage-Timestamp: <unix seconds>``
               ``X-Triage-Signature: v1=<hex digest>``

The timestamp bounds replay of a captured request to `max_skew` seconds; within that
window the deterministic alert_id makes a replayed body a no-op.
"""

from __future__ import annotations

import hashlib
import hmac
import time

TIMESTAMP_HEADER = "X-Triage-Timestamp"
SIGNATURE_HEADER = "X-Triage-Signature"
SCHEME = "v1"


class SignatureError(Exception):
    pass


def sign(secret: bytes, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {TIMESTAMP_HEADER: str(ts), SIGNATURE_HEADER: f"{SCHEME}={digest}"}


def verify(
    secrets: list[bytes],
    body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    *,
    max_skew: int = 300,
    now: float | None = None,
) -> None:
    if not secrets:
        raise SignatureError("no signing secrets configured")
    if not timestamp_header or not signature_header:
        raise SignatureError("missing signature headers")
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise SignatureError("malformed timestamp") from exc
    current = time.time() if now is None else now
    if abs(current - ts) > max_skew:
        raise SignatureError("timestamp outside allowed window")

    provided = [
        part.split("=", 1)[1]
        for part in signature_header.split(",")
        if part.strip().startswith(f"{SCHEME}=")
    ]
    if not provided:
        raise SignatureError("no v1 signature")
    message = f"{ts}.".encode() + body
    for secret in secrets:
        expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
        if any(hmac.compare_digest(expected, p.strip()) for p in provided):
            return
    raise SignatureError("signature mismatch")
