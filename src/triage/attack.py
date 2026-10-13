"""MITRE ATT&CK (Enterprise) technique catalogue.

`build_catalog()` turns the STIX bundle into one record per live technique plus a map of
revoked IDs to their replacements; `Catalog.load()` reads the committed JSONL snapshot.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def clean_description(text: str) -> str:
    text = _CITATION.sub("", text or "")
    text = _MD_LINK.sub(r"\1", text)
    text = _HTML.sub("", text)
    return _WS.sub(" ", text).strip()


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    is_subtechnique: bool
    parent_id: str | None
    url: str
    description: str
    parent_name: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.parent_name}: {self.name}" if self.parent_name else self.name

    def summary(self, limit: int = 240) -> str:
        first = self.description.split(". ")[0]
        return (first[: limit - 1] + "…") if len(first) > limit else first

    def chunk(self) -> str:
        """Text embedded for retrieval: one chunk per technique."""
        return (
            f"{self.id} {self.full_name}. Tactics: {', '.join(self.tactics)}. "
            f"Platforms: {', '.join(self.platforms)}. {self.description[:2000]}"
        )


@dataclass
class Catalog:
    techniques: dict[str, Technique]
    revoked: dict[str, str] = field(default_factory=dict)
    version: str = "unknown"

    def resolve(self, technique_id: str) -> str | None:
        """Map revoked/old IDs forward; return None for IDs that are not techniques."""
        tid = technique_id.upper().strip()
        seen = set()
        while tid in self.revoked and tid not in seen:
            seen.add(tid)
            tid = self.revoked[tid]
        return tid if tid in self.techniques else None

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        t = self.techniques.get(technique_id)
        return t.tactics if t else ()

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "techniques.jsonl").open("w") as fh:
            for t in sorted(self.techniques.values(), key=lambda t: t.id):
                fh.write(json.dumps(asdict(t)) + "\n")
        (directory / "revoked.json").write_text(json.dumps(dict(sorted(self.revoked.items())), indent=0) + "\n")
        (directory / "MANIFEST.json").write_text(
            json.dumps({"attack_version": self.version, "techniques": len(self.techniques),
                        "revoked": len(self.revoked)}, indent=2) + "\n"
        )

    @classmethod
    def load(cls, directory: Path | str) -> Catalog:
        directory = Path(directory)
        if directory.suffix == ".jsonl":
            directory = directory.parent
        techniques = {}
        with (directory / "techniques.jsonl").open() as fh:
            for line in fh:
                d = json.loads(line)
                d["tactics"], d["platforms"] = tuple(d["tactics"]), tuple(d["platforms"])
                techniques[d["id"]] = Technique(**d)
        revoked = json.loads((directory / "revoked.json").read_text())
        version = json.loads((directory / "MANIFEST.json").read_text()).get("attack_version", "unknown")
        return cls(techniques, revoked, version)


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_catalog(stix_path: Path) -> Catalog:
    bundle = json.loads(stix_path.read_text())
    objects = bundle["objects"]
    version = next((o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), "unknown")
    patterns = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    stix_to_ext = {sid: _external_id(o) for sid, o in patterns.items()}

    live: dict[str, dict] = {}
    for o in patterns.values():
        ext = stix_to_ext[o["id"]]
        if not ext or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        live[ext] = o

    revoked: dict[str, str] = {}
    for rel in (o for o in objects if o["type"] == "relationship" and o["relationship_type"] == "revoked-by"):
        old, new = stix_to_ext.get(rel["source_ref"]), stix_to_ext.get(rel["target_ref"])
        if old and new and old != new:
            revoked[old] = new

    techniques: dict[str, Technique] = {}
    for ext, o in live.items():
        is_sub = bool(o.get("x_mitre_is_subtechnique"))
        parent = ext.split(".")[0] if is_sub else None
        url = next((r.get("url", "") for r in o["external_references"] if r.get("source_name") == "mitre-attack"), "")
        techniques[ext] = Technique(
            id=ext,
            name=o["name"],
            tactics=tuple(p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"),
            platforms=tuple(o.get("x_mitre_platforms", [])),
            is_subtechnique=is_sub,
            parent_id=parent,
            url=url,
            description=clean_description(o.get("description", "")),
            parent_name=live[parent]["name"] if parent and parent in live else None,
        )
    return Catalog(techniques, revoked, str(version))


@lru_cache(maxsize=4)
def load_catalog(directory: str) -> Catalog:
    return Catalog.load(directory)
