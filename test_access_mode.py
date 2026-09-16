import asyncio
from fastapi import HTTPException, Response

from app.main import app, request_otp, verify_access_otp, settings
from app.schemas import IdentifyRequest, OTPVerifyRequest


class DummyRequest:
    headers = {}
    cookies = {}
    client = None


def test_superadmin_mode_is_canonical():
    assert settings.access_approval_mode == "superadmin"


def test_visitor_request_otp_is_blocked_in_superadmin_mode():
    payload = IdentifyRequest(
        token="x" * 40,
        name="Visitante Teste",
        email="visitante@example.com",
        organization="Empresa Teste",
        role="Diretor",
    )
    try:
        asyncio.run(request_otp(payload, DummyRequest(), None))
        assert False, "visitor OTP route should be blocked"
    except HTTPException as exc:
        assert exc.status_code == 404


def test_visitor_verify_otp_is_blocked_in_superadmin_mode():
    payload = OTPVerifyRequest(token="x" * 40, code="123456")
    try:
        verify_access_otp(payload, DummyRequest(), Response(), None)
        assert False, "visitor OTP verify route should be blocked"
    except HTTPException as exc:
        assert exc.status_code == 404


def test_admin_otp_routes_remain_registered():
    paths = {route.path for route in app.routes}
    assert "/api/admin/auth/start" in paths
    assert "/api/admin/auth/verify" in paths
