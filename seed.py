from pathlib import Path
import json, hashlib
from sqlalchemy import select
from .db import SessionLocal
from .models import Project, LegalTerm
from .storage import get_storage
from .config import get_settings

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "private_seed"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def seed():
    settings = get_settings()
    if not settings.seed_content_on_startup:
        return
    storage = get_storage()
    db = SessionLocal()
    try:
        project = db.scalar(select(Project).where(Project.slug == "estevez-guarda"))
        if not project:
            project = Project(slug="estevez-guarda", name="Projeto Estevez Guarda")
            db.add(project); db.flush()

        term_bytes = (SEED / "legal/term_v1.md").read_bytes()
        privacy_bytes = (SEED / "legal/privacy_notice_v1.md").read_bytes()
        term_sha = sha256(term_bytes)

        term_key = f"projects/{project.slug}/legal/term-v1-{term_sha[:12]}.md"
        privacy_key = f"projects/{project.slug}/legal/privacy-v1.md"
        if not storage.exists(term_key):
            storage.put(term_key, term_bytes, "text/markdown; charset=utf-8")
        if not storage.exists(privacy_key):
            storage.put(privacy_key, privacy_bytes, "text/markdown; charset=utf-8")

        term = db.scalar(select(LegalTerm).where(LegalTerm.project_id == project.id, LegalTerm.version == "1.0"))
        if not term:
            term = LegalTerm(
                project_id=project.id,
                name="Termo de Confidencialidade e Condições de Acesso a Material Restrito",
                version="1.0",
                document_sha256=term_sha,
                document_storage_key=term_key,
                privacy_storage_key=privacy_key,
                requires_reacceptance=True,
            )
            db.add(term)

        pres_bytes = (SEED / "presentation.json").read_bytes()
        pres = json.loads(pres_bytes)
        pres_key = f"projects/{project.slug}/presentation/{pres['version']}.json"
        if not storage.exists(pres_key):
            storage.put(pres_key, pres_bytes, "application/json")

        for asset in (SEED / "assets").glob("*"):
            key = f"projects/{project.slug}/assets/{asset.name}"
            if not storage.exists(key):
                storage.put(key, asset.read_bytes(), "image/webp")

        db.commit()
        print(f"Seed OK. Term SHA-256: {term_sha}")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
