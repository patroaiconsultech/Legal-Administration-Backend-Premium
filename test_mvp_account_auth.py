from pathlib import Path
from app.main import app
from app.models import PortalAccount
from app.security import hash_password, verify_password

def test_mvp_account_routes_registered():
    paths={route.path for route in app.routes}
    expected={
        "/api/account/activation/start",
        "/api/account/activation/complete",
        "/api/account/login",
        "/api/account/logout",
        "/api/account/me",
    }
    assert expected.issubset(paths)

def test_portal_account_model_contract():
    cols={c.name for c in PortalAccount.__table__.columns}
    assert {"project_id","invitation_id","email","password_hash","state","activated_at","last_login_at"}.issubset(cols)

def test_portal_password_roundtrip():
    encoded=hash_password("MvpPassword123")
    assert verify_password("MvpPassword123", encoded)
    assert not verify_password("wrong-password", encoded)

def test_portal_migration_present():
    p=Path("alembic/versions/003_portal_accounts.py")
    text=p.read_text(encoding="utf-8")
    assert 'revision = "003_portal_accounts"' in text
    assert 'down_revision = "002_superadmin_access_requests"' in text
