import json, uuid
from fastapi import Request
from sqlalchemy.orm import Session
from .models import AuditEvent

def request_id(request: Request) -> str:
    return request.headers.get("x-request-id") or str(uuid.uuid4())

def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None

def log_event(
    db: Session, request: Request, event_type: str, *,
    project_id=None, invitation_id=None, acceptance_id=None, access_session_id=None, metadata=None
):
    evt = AuditEvent(
        project_id=project_id,
        invitation_id=invitation_id,
        acceptance_id=acceptance_id,
        access_session_id=access_session_id,
        event_type=event_type,
        request_id=request_id(request),
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(evt)
    db.flush()
    return evt
