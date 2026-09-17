import json, hashlib, secrets, html
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request, Response, Cookie, Header
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, desc, func
from sqlalchemy.orm import Session
from .config import get_settings
from .db import db_session, engine
from .models import *
from .schemas import *
from .security import *
from .audit import log_event, client_ip
from .emailer import send_email
from .storage import get_storage
from .receipt import build_receipt
from .agent import answer as agent_answer
from .push import send_admin_push, push_available

settings = get_settings()
storage = get_storage()
app = FastAPI(title=settings.app_name, docs_url=None if settings.environment == "production" else "/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET","POST"],
    allow_headers=["Content-Type","X-CSRF-Token","X-Request-ID"],
)

def now():
    return datetime.utcnow()

def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    no_store(response)
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return response

def _invite(db: Session, token: str) -> Invitation:
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == sha256_text(token)))
    if not inv or inv.revoked_at or inv.expires_at <= now():
        raise HTTPException(404, "Convite inválido, expirado ou revogado.")
    return inv

def _session(db: Session, raw: str | None) -> AccessSession:
    if not raw:
        raise HTTPException(401, "Sessão ausente.")
    s = db.scalar(select(AccessSession).where(AccessSession.session_token_hash == sha256_text(raw)))
    if not s or s.revoked_at or s.expires_at <= now():
        raise HTTPException(401, "Sessão inválida ou expirada.")
    return s

def _admin_session(db: Session, raw: str | None) -> AdminSession:
    if not raw:
        raise HTTPException(401, "Sessão administrativa ausente.")
    s = db.scalar(select(AdminSession).where(AdminSession.session_token_hash == sha256_text(raw)))
    if not s or s.revoked_at or s.expires_at <= now():
        raise HTTPException(401, "Sessão administrativa inválida.")
    return s

def verify_csrf(request: Request, header: str | None):
    cookie = request.cookies.get("efata_csrf")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF inválido.")

def verify_admin_csrf(request: Request, header: str | None):
    cookie = request.cookies.get("efata_admin_csrf")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF administrativo inválido.")

def require_visitor_otp_enabled() -> None:
    """
    Visitor OTP is legacy behavior and is intentionally unavailable in the
    canonical superadmin admission mode. Admin OTP is a separate control.
    """
    if settings.access_approval_mode == "superadmin":
        raise HTTPException(status_code=404, detail="Rota indisponível neste modo de acesso.")

def current_term(db: Session, project_id: str) -> LegalTerm:
    term = db.scalar(
        select(LegalTerm)
        .where(LegalTerm.project_id == project_id, LegalTerm.superseded_at.is_(None))
        .order_by(desc(LegalTerm.published_at))
    )
    if not term:
        raise HTTPException(503, "Termo não publicado.")
    return term


def normalize_email(value: str) -> str:
    return value.strip().lower()

def request_fingerprint(request: Request, email: str) -> str:
    ua = (request.headers.get("user-agent") or "")[:240]
    material = f"{normalize_email(email)}|{ua}"
    return sha256_text(material)

def observed_ip(request: Request) -> str | None:
    # Deliberately uses the socket peer only. A trusted-proxy contract may later
    # promote an edge-provided address into a separate canonical field.
    return request.client.host if request.client else None


async def notify_admin_access_request(
    db: Session, request: Request, *, project_id: str, request_id: str,
    full_name: str, organization_name: str,
) -> str:
    """Send and audit the admin notification without hiding delivery failures."""
    try:
        result = await send_email(
            settings.admin_email,
            "Nova solicitação de acesso — Efatá",
            f"<p>Uma nova solicitação de acesso ao briefing confidencial aguarda sua revisão.</p>"
            f"<p><b>Nome:</b> {html.escape(full_name)}<br>"
            f"<b>Organização:</b> {html.escape(organization_name)}</p>"
            f"<p>Abra o painel administrativo da Efatá para aprovar ou rejeitar.</p>"
        )
    except Exception as exc:
        db.rollback()
        log_event(
            db, request, "ACCESS_REQUEST_EMAIL_FAILED", project_id=project_id,
            metadata={
                "access_request_id": request_id,
                "recipient": settings.admin_email,
                "error_type": type(exc).__name__,
                "error_message": str(exc)[:240],
            },
        )
        db.commit()
        return "failed"

    provider_id = result.get("id") if isinstance(result, dict) else None
    log_event(
        db, request, "ACCESS_REQUEST_EMAIL_SENT", project_id=project_id,
        metadata={
            "access_request_id": request_id,
            "recipient": settings.admin_email,
            "provider_message_id": provider_id,
        },
    )
    db.commit()
    return "sent"


@app.get("/health")
def health():
    return {"status":"ok","service":"efata-secure-briefing"}


@app.post("/api/access-requests")
async def create_access_request(payload: AccessRequestCreate, request: Request, db: Session = Depends(db_session)):
    if not settings.access_request_enabled:
        raise HTTPException(404, "Solicitação de acesso indisponível.")
    project = db.scalar(select(Project).where(Project.slug == "estevez-guarda"))
    if not project:
        raise HTTPException(503, "Projeto indisponível.")

    email = normalize_email(str(payload.email))
    fp = request_fingerprint(request, email)
    window_start = now() - timedelta(minutes=settings.access_request_window_minutes)
    recent_count = db.scalar(
        select(func.count(AccessRequest.id)).where(
            AccessRequest.request_fingerprint_hash == fp,
            AccessRequest.requested_at >= window_start,
        )
    ) or 0
    if recent_count >= settings.access_request_max_per_window:
        log_event(db, request, "ACCESS_REQUEST_RATE_LIMITED", project_id=project.id, metadata={"fingerprint": fp[:16]})
        db.commit()
        raise HTTPException(429, "Muitas solicitações. Aguarde e tente novamente.")

    existing = db.scalar(
        select(AccessRequest).where(
            AccessRequest.project_id == project.id,
            AccessRequest.email == email,
            AccessRequest.state == "PENDING_ADMIN_APPROVAL",
        ).order_by(desc(AccessRequest.requested_at))
    )
    if existing:
        email_notification = await notify_admin_access_request(
            db, request, project_id=project.id, request_id=existing.id,
            full_name=existing.full_name, organization_name=existing.organization_name,
        )
        return {
            "status": "PENDING_ADMIN_APPROVAL",
            "request_id": existing.id,
            "email_notification": email_notification,
        }

    row = AccessRequest(
        project_id=project.id,
        full_name=payload.full_name.strip(),
        email=email,
        organization_name=payload.organization.strip(),
        recipient_role=payload.role.strip(),
        purpose=payload.purpose.strip(),
        state="PENDING_ADMIN_APPROVAL",
        request_fingerprint_hash=fp,
        request_ip=observed_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:1000],
    )
    db.add(row); db.flush()
    log_event(
        db, request, "ACCESS_REQUEST_CREATED", project_id=project.id,
        metadata={"access_request_id": row.id, "organization": row.organization_name[:120]}
    )
    db.commit()

    # Notification is best-effort. The DB row is the source of truth.
    push_summary = {"enabled": False}
    try:
        push_summary = send_admin_push(
            db,
            title="Nova solicitação de acesso — Efatá",
            body="Há uma nova solicitação aguardando sua revisão.",
            url=f"/admin?request={row.id}",
        )
        db.commit()
    except Exception:
        db.rollback()

    email_notification = await notify_admin_access_request(
        db, request, project_id=project.id, request_id=row.id,
        full_name=row.full_name, organization_name=row.organization_name,
    )
    return {
        "status": "PENDING_ADMIN_APPROVAL",
        "request_id": row.id,
        "email_notification": email_notification,
    }


@app.post("/api/access/consume")
def consume_approved_access(payload: AccessConsumeRequest, request: Request, response: Response, db: Session = Depends(db_session)):
    token_hash = sha256_text(payload.token)
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == token_hash).with_for_update())
    if not inv or inv.revoked_at or inv.expires_at <= now():
        raise HTTPException(404, "Link inválido, expirado ou revogado.")
    if inv.link_consumed_at is not None:
        raise HTTPException(409, "Este link de acesso já foi utilizado.")

    inv.link_consumed_at = now()
    inv.email_verified_at = now()
    raw = random_token()
    s = AccessSession(
        invitation_id=inv.id,
        session_token_hash=sha256_text(raw),
        email_verified_at=inv.email_verified_at,
        expires_at=expires(hours=settings.access_session_hours),
    )
    db.add(s); db.flush()
    log_event(
        db, request, "APPROVAL_LINK_CONSUMED",
        project_id=inv.project_id, invitation_id=inv.id, access_session_id=s.id
    )
    db.commit()

    csrf = random_token(24)
    response.set_cookie("efata_secure_session", raw, httponly=True, secure=settings.cookie_secure, samesite="strict", max_age=settings.access_session_hours*3600, path="/")
    response.set_cookie("efata_csrf", csrf, httponly=False, secure=settings.cookie_secure, samesite="strict", max_age=settings.access_session_hours*3600, path="/")
    return {"ok": True, "csrf": csrf}


@app.get("/api/invite/{token}")
def invite_info(token: str, request: Request, db: Session = Depends(db_session)):
    inv = _invite(db, token)
    log_event(db, request, "LINK_OPENED", project_id=inv.project_id, invitation_id=inv.id)
    db.commit()
    email = inv.recipient_email
    masked = email[:2] + "***@" + email.split("@",1)[1]
    return {"project":"Projeto Estevez Guarda","recipient_email_masked":masked,"organization":inv.organization_name,"expires_at":inv.expires_at}

@app.post("/api/auth/request-otp")
async def request_otp(payload: IdentifyRequest, request: Request, db: Session = Depends(db_session)):
    require_visitor_otp_enabled()
    inv = _invite(db, payload.token)
    if payload.email.lower().strip() != inv.recipient_email.lower().strip():
        log_event(db, request, "IDENTIFICATION_EMAIL_MISMATCH", project_id=inv.project_id, invitation_id=inv.id)
        db.commit()
        raise HTTPException(403, "O e-mail informado não corresponde ao destinatário do convite.")

    recent = db.scalar(select(OTPChallenge).where(
        OTPChallenge.subject_type=="INVITATION", OTPChallenge.subject_id==inv.id, OTPChallenge.purpose=="ACCESS"
    ).order_by(desc(OTPChallenge.issued_at)))
    if recent and recent.issued_at > now() - timedelta(seconds=45):
        raise HTTPException(429, "Aguarde antes de solicitar novo código.")

    inv.recipient_name = payload.name.strip()
    inv.organization_name = payload.organization.strip()
    inv.recipient_role = payload.role.strip()
    code = otp_code()
    ch = OTPChallenge(
        subject_type="INVITATION", subject_id=inv.id, purpose="ACCESS",
        otp_hash=hash_otp(code), expires_at=expires(minutes=settings.otp_minutes)
    )
    db.add(ch)
    log_event(db, request, "IDENTIFICATION_SUBMITTED", project_id=inv.project_id, invitation_id=inv.id)
    log_event(db, request, "OTP_SENT", project_id=inv.project_id, invitation_id=inv.id)
    db.commit()
    await send_email(
        inv.recipient_email,
        "Seu código de acesso — Efatá",
        f"<p>Seu código temporário para o portal confidencial Efatá é:</p><h2>{code}</h2><p>Validade: {settings.otp_minutes} minutos. Não compartilhe este código.</p>"
    )
    return {"ok":True,"message":"Código enviado ao e-mail do convite."}

@app.post("/api/auth/verify-otp")
def verify_access_otp(payload: OTPVerifyRequest, request: Request, response: Response, db: Session = Depends(db_session)):
    require_visitor_otp_enabled()
    inv = _invite(db, payload.token)
    ch = db.scalar(select(OTPChallenge).where(
        OTPChallenge.subject_type=="INVITATION",
        OTPChallenge.subject_id==inv.id,
        OTPChallenge.purpose=="ACCESS",
        OTPChallenge.validated_at.is_(None),
        OTPChallenge.invalidated_at.is_(None),
    ).order_by(desc(OTPChallenge.issued_at)))
    if not ch or ch.expires_at <= now():
        raise HTTPException(400, "Código expirado ou inexistente.")
    ch.attempt_count += 1
    if ch.attempt_count > settings.otp_max_attempts:
        ch.invalidated_at = now(); db.commit()
        raise HTTPException(429, "Número máximo de tentativas excedido.")
    if not verify_otp(payload.code, ch.otp_hash):
        db.commit()
        raise HTTPException(400, "Código inválido.")
    ch.validated_at = now()
    inv.email_verified_at = now()

    raw = random_token()
    s = AccessSession(
        invitation_id=inv.id,
        session_token_hash=sha256_text(raw),
        email_verified_at=now(),
        expires_at=expires(hours=settings.access_session_hours),
    )
    db.add(s); db.flush()
    log_event(db, request, "OTP_VALIDATED", project_id=inv.project_id, invitation_id=inv.id, access_session_id=s.id)
    db.commit()

    csrf = random_token(24)
    response.set_cookie("efata_secure_session", raw, httponly=True, secure=settings.cookie_secure, samesite="strict", max_age=settings.access_session_hours*3600, path="/")
    response.set_cookie("efata_csrf", csrf, httponly=False, secure=settings.cookie_secure, samesite="strict", max_age=settings.access_session_hours*3600, path="/")
    return {"ok":True,"csrf":csrf}

@app.get("/api/legal/term")
def get_term(request: Request, db: Session = Depends(db_session), efata_secure_session: str | None = Cookie(default=None)):
    s = _session(db, efata_secure_session)
    inv = db.get(Invitation, s.invitation_id)
    term = current_term(db, inv.project_id)
    data, _ = storage.get(term.document_storage_key)
    privacy, _ = storage.get(term.privacy_storage_key) if term.privacy_storage_key else (b"", "text/plain")
    log_event(db, request, "TERM_RENDERED", project_id=inv.project_id, invitation_id=inv.id, access_session_id=s.id, metadata={"term_version":term.version})
    db.commit()
    return {"name":term.name,"version":term.version,"sha256":term.document_sha256,"content":data.decode(),"privacy_notice":privacy.decode()}

@app.post("/api/legal/accept")
async def accept_term(payload: AcceptRequest, request: Request, response: Response, db: Session = Depends(db_session),
                      efata_secure_session: str | None = Cookie(default=None), x_csrf_token: str | None = Header(default=None)):
    verify_csrf(request, x_csrf_token)
    if not payload.accepted:
        raise HTTPException(400, "Aceite expresso é obrigatório.")
    if payload.representation_mode not in {"PERSONAL","PERSONAL_AND_ORGANIZATION"}:
        raise HTTPException(400, "Forma de vinculação inválida.")
    s = _session(db, efata_secure_session)
    inv = db.get(Invitation, s.invitation_id)
    if not all([inv.recipient_name, inv.recipient_role, inv.email_verified_at]):
        raise HTTPException(409, "Identificação incompleta.")
    term = current_term(db, inv.project_id)

    existing = db.scalar(select(LegalAcceptance).where(
        LegalAcceptance.invitation_id==inv.id,
        LegalAcceptance.term_id==term.id,
        LegalAcceptance.recipient_email==inv.recipient_email
    ).order_by(desc(LegalAcceptance.accepted_at)))

    if existing:
        acc = existing
    else:
        declaration = payload.representation_declaration
        if payload.representation_mode == "PERSONAL_AND_ORGANIZATION" and not declaration:
            declaration = "Declaro possuir poderes suficientes para aceitar estas obrigações também em nome da organização informada."
        acc = LegalAcceptance(
            project_id=inv.project_id,
            term_id=term.id,
            invitation_id=inv.id,
            term_version=term.version,
            term_document_sha256=term.document_sha256,
            recipient_name=inv.recipient_name,
            recipient_email=inv.recipient_email,
            organization_name=inv.organization_name,
            recipient_role=inv.recipient_role,
            representation_mode=payload.representation_mode,
            representation_declaration=declaration,
            authentication_method="ADMIN_APPROVED_MAGIC_LINK",
            email_verified_at=inv.email_verified_at,
            timezone=payload.timezone,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        db.add(acc); db.flush()

        receipt = build_receipt({
            "acceptance_id":acc.id, "evidence_id":acc.evidence_id,
            "term_version":acc.term_version, "term_sha256":acc.term_document_sha256,
            "recipient_name":acc.recipient_name, "recipient_email":acc.recipient_email,
            "organization":acc.organization_name, "role":acc.recipient_role,
            "representation_mode":acc.representation_mode,
            "accepted_at":acc.accepted_at.isoformat()+"Z", "timezone":acc.timezone
        })
        rsha = hashlib.sha256(receipt).hexdigest()
        rkey = f"projects/estevez-guarda/receipts/{acc.id}-{rsha[:12]}.pdf"
        storage.put(rkey, receipt, "application/pdf")
        acc.receipt_storage_key = rkey
        acc.receipt_sha256 = rsha

    s.acceptance_id = acc.id
    s.authorized_at = now()
    log_event(db, request, "ACCEPTANCE_COMMITTED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id,
              metadata={"term_version":term.version,"term_sha256":term.document_sha256})
    log_event(db, request, "SESSION_AUTHORIZED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id)
    db.commit()

    await send_email(
        acc.recipient_email,
        "Comprovante de aceite — Efatá",
        f"<p>Seu aceite foi registrado.</p><p><b>Aceite:</b> {acc.id}<br><b>Termo:</b> v{acc.term_version}<br><b>SHA-256:</b> {acc.term_document_sha256}</p><p>O comprovante permanece disponível no portal durante sua sessão autorizada.</p>"
    )
    return {"ok":True,"acceptance_id":acc.id,"evidence_id":acc.evidence_id,"access_id":acc.access_id,"term_sha256":acc.term_document_sha256}

def require_authorized(db: Session, raw: str | None):
    s = _session(db, raw)
    if not s.authorized_at or not s.acceptance_id:
        raise HTTPException(403, "Aceite de confidencialidade obrigatório.")
    inv = db.get(Invitation, s.invitation_id)
    acc = db.get(LegalAcceptance, s.acceptance_id)
    term = current_term(db, inv.project_id)
    if term.requires_reacceptance and acc.term_id != term.id:
        raise HTTPException(428, "Novo aceite obrigatório.")
    return s, inv, acc, term

@app.get("/api/content/presentation")
def content(request: Request, db: Session = Depends(db_session), efata_secure_session: str | None = Cookie(default=None)):
    s, inv, acc, term = require_authorized(db, efata_secure_session)
    key_prefix = "projects/estevez-guarda/presentation/"
    # seeded version is deterministic in this package
    key = key_prefix + "2026-09-16.3.json"
    data, _ = storage.get(key)
    payload = json.loads(data)
    payload["viewer"] = {
        "name":acc.recipient_name, "organization":acc.organization_name, "access_id":acc.access_id,
        "agent_enabled":settings.agent_enabled,
    }
    log_event(db, request, "CONTENT_ACCESSED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id,
              metadata={"content":"presentation","version":payload["version"]})
    db.commit()
    return payload

@app.get("/api/content/asset/{asset_name}")
def content_asset(asset_name: str, request: Request, db: Session = Depends(db_session), efata_secure_session: str | None = Cookie(default=None)):
    s, inv, acc, term = require_authorized(db, efata_secure_session)
    allowed = {"hero":"hero.webp","architecture":"architecture.webp","waiting":"waiting.webp"}
    if asset_name not in allowed:
        raise HTTPException(404)
    data, ct = storage.get(f"projects/estevez-guarda/assets/{allowed[asset_name]}")
    log_event(db, request, "CONTENT_ASSET_ACCESSED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id, metadata={"asset":asset_name})
    db.commit()
    return Response(content=data, media_type=ct, headers={"Cache-Control":"no-store, private"})

@app.get("/api/legal/receipt")
def receipt(request: Request, db: Session = Depends(db_session), efata_secure_session: str | None = Cookie(default=None)):
    s, inv, acc, term = require_authorized(db, efata_secure_session)
    data, ct = storage.get(acc.receipt_storage_key)
    return Response(content=data, media_type=ct, headers={"Content-Disposition":f'attachment; filename="aceite-{acc.id}.pdf"'})

@app.post("/api/agent/chat")
async def agent_chat(payload: AgentChatRequest, request: Request, db: Session = Depends(db_session),
                     efata_secure_session: str | None = Cookie(default=None), x_csrf_token: str | None = Header(default=None)):
    verify_csrf(request, x_csrf_token)
    s, inv, acc, term = require_authorized(db, efata_secure_session)
    if not settings.agent_enabled:
        raise HTTPException(503, "Hyper Agente ainda não habilitado para este ambiente.")

    thread = None
    if payload.thread_id:
        thread = db.get(AgentThread, payload.thread_id)
        if not thread or thread.acceptance_id != acc.id:
            raise HTTPException(404, "Conversa não encontrada.")
    if not thread:
        thread = AgentThread(project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, title=payload.question[:120])
        db.add(thread); db.flush()

    qsha = sha256_text(payload.question)
    db.add(AgentMessage(thread_id=thread.id, role="user", content=payload.question if settings.agent_store_content else None, content_sha256=qsha))
    log_event(db, request, "AGENT_QUESTION_SUBMITTED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id,
              metadata={"thread_id":thread.id,"question_sha256":qsha})
    db.commit()

    text, sources, model = await agent_answer(payload.question)
    asha = sha256_text(text)
    db.add(AgentMessage(thread_id=thread.id, role="assistant", content=text if settings.agent_store_content else None, content_sha256=asha, model=model, sources_json=json.dumps(sources)))
    thread.updated_at = now()
    log_event(db, request, "AGENT_RESPONSE_RETURNED", project_id=inv.project_id, invitation_id=inv.id, acceptance_id=acc.id, access_session_id=s.id,
              metadata={"thread_id":thread.id,"answer_sha256":asha,"model":model,"sources":sources})
    db.commit()
    return {"thread_id":thread.id,"answer":text,"sources":sources}

# ---------------------- ADMIN: password + OTP -----------------------
@app.post("/api/admin/auth/start")
async def admin_start(payload: AdminStartRequest, request: Request, db: Session = Depends(db_session)):
    from .security import verify_password
    if payload.email.lower() != settings.admin_email.lower() or not verify_password(payload.password, settings.admin_password_hash):
        raise HTTPException(401, "Credenciais inválidas.")
    recent = db.scalar(select(OTPChallenge).where(
        OTPChallenge.subject_type=="ADMIN", OTPChallenge.subject_id==payload.email.lower(), OTPChallenge.purpose=="ADMIN_LOGIN"
    ).order_by(desc(OTPChallenge.issued_at)))
    if recent and recent.issued_at > now() - timedelta(seconds=45):
        raise HTTPException(429, "Aguarde antes de solicitar novo código.")
    code = otp_code()
    ch = OTPChallenge(subject_type="ADMIN", subject_id=payload.email.lower(), purpose="ADMIN_LOGIN", otp_hash=hash_otp(code), expires_at=expires(minutes=settings.otp_minutes))
    db.add(ch); db.commit()
    await send_email(payload.email, "Código administrativo — Efatá", f"<p>Código de autenticação administrativa:</p><h2>{code}</h2>")
    return {"ok":True}

@app.post("/api/admin/auth/verify")
def admin_verify(payload: AdminVerifyRequest, response: Response, db: Session = Depends(db_session)):
    if payload.email.lower() != settings.admin_email.lower():
        raise HTTPException(401)
    ch = db.scalar(select(OTPChallenge).where(
        OTPChallenge.subject_type=="ADMIN", OTPChallenge.subject_id==payload.email.lower(), OTPChallenge.purpose=="ADMIN_LOGIN",
        OTPChallenge.validated_at.is_(None), OTPChallenge.invalidated_at.is_(None)
    ).order_by(desc(OTPChallenge.issued_at)))
    if not ch or ch.expires_at <= now():
        raise HTTPException(400, "Código expirado.")
    ch.attempt_count += 1
    if ch.attempt_count > settings.otp_max_attempts:
        ch.invalidated_at=now(); db.commit(); raise HTTPException(429)
    if not verify_otp(payload.code, ch.otp_hash):
        db.commit(); raise HTTPException(400, "Código inválido.")
    ch.validated_at=now()
    raw=random_token()
    sess=AdminSession(admin_email=payload.email.lower(), session_token_hash=sha256_text(raw), expires_at=expires(hours=4))
    db.add(sess); db.commit()
    csrf=random_token(24)
    response.set_cookie("efata_admin_session",raw,httponly=True,secure=settings.cookie_secure,samesite="strict",max_age=14400,path="/")
    response.set_cookie("efata_admin_csrf",csrf,httponly=False,secure=settings.cookie_secure,samesite="strict",max_age=14400,path="/")
    return {"ok":True,"csrf":csrf}

def admin_auth(db, raw):
    return _admin_session(db, raw)


@app.get("/api/admin/push/public-key")
def admin_push_public_key(db: Session = Depends(db_session), efata_admin_session: str | None = Cookie(default=None)):
    admin_auth(db, efata_admin_session)
    return {"enabled": push_available(), "public_key": settings.vapid_public_key if push_available() else None}

@app.post("/api/admin/push/subscribe")
def admin_push_subscribe(payload: PushSubscriptionCreate, request: Request, db: Session = Depends(db_session),
                         efata_admin_session: str | None = Cookie(default=None), x_csrf_token: str | None = Header(default=None)):
    verify_admin_csrf(request, x_csrf_token)
    sess = admin_auth(db, efata_admin_session)
    row = db.scalar(select(PushSubscription).where(PushSubscription.endpoint == payload.endpoint))
    if row:
        row.admin_email = sess.admin_email
        row.p256dh = payload.p256dh
        row.auth = payload.auth
        row.revoked_at = None
        row.failure_count = 0
    else:
        row = PushSubscription(admin_email=sess.admin_email, endpoint=payload.endpoint, p256dh=payload.p256dh, auth=payload.auth)
        db.add(row)
    db.commit()
    return {"ok": True}

@app.get("/api/admin/access-requests")
def admin_access_requests(db: Session = Depends(db_session), efata_admin_session: str | None = Cookie(default=None)):
    admin_auth(db, efata_admin_session)
    rows = db.scalars(select(AccessRequest).order_by(desc(AccessRequest.requested_at)).limit(200)).all()
    return [{
        "id": r.id,
        "full_name": r.full_name,
        "email": r.email,
        "organization": r.organization_name,
        "role": r.recipient_role,
        "purpose": r.purpose,
        "state": r.state,
        "requested_at": r.requested_at,
        "reviewed_at": r.reviewed_at,
        "reviewed_by": r.reviewed_by,
        "review_reason": r.review_reason,
        "approved_invitation_id": r.approved_invitation_id,
        "approval_notified_at": r.approval_notified_at,
        "approval_delivery_error": r.approval_delivery_error,
    } for r in rows]

@app.post("/api/admin/access-requests/{access_request_id}/approve")
async def admin_approve_access_request(access_request_id: str, payload: AdminAccessDecision, request: Request,
                                       db: Session = Depends(db_session),
                                       efata_admin_session: str | None = Cookie(default=None),
                                       x_csrf_token: str | None = Header(default=None)):
    verify_admin_csrf(request, x_csrf_token)
    sess = admin_auth(db, efata_admin_session)
    row = db.scalar(select(AccessRequest).where(AccessRequest.id == access_request_id).with_for_update())
    if not row:
        raise HTTPException(404, "Solicitação não encontrada.")
    if row.state != "PENDING_ADMIN_APPROVAL":
        raise HTTPException(409, f"Solicitação já está em estado {row.state}.")

    token = random_token(32)
    inv = Invitation(
        project_id=row.project_id,
        token_hash=sha256_text(token),
        recipient_email=row.email,
        recipient_name=row.full_name,
        organization_name=row.organization_name,
        recipient_role=row.recipient_role,
        expires_at=expires(hours=settings.approval_link_hours),
    )
    db.add(inv); db.flush()
    row.state = "APPROVED"
    row.reviewed_at = now()
    row.reviewed_by = sess.admin_email
    row.review_reason = payload.reason.strip()
    row.approved_invitation_id = inv.id
    log_event(
        db, request, "ACCESS_REQUEST_APPROVED",
        project_id=row.project_id, invitation_id=inv.id,
        metadata={"access_request_id": row.id, "admin_email": sess.admin_email}
    )
    db.commit()

    link = f"{settings.public_base_url.rstrip('/')}/a/{token}"
    try:
        await send_email(
            row.email,
            "Acesso aprovado — Efatá",
            f"<p>Seu acesso ao briefing confidencial do Projeto Esteves foi aprovado.</p>"
            f"<p><a href='{html.escape(link)}'>Acessar briefing confidencial</a></p>"
            f"<p>O link é individual, de uso único e expira em {settings.approval_link_hours} horas.</p>"
        )
        row.approval_notified_at = now()
        row.approval_delivery_error = None
        log_event(db, request, "APPROVAL_LINK_SENT", project_id=row.project_id, invitation_id=inv.id,
                  metadata={"access_request_id": row.id})
        db.commit()
    except Exception:
        row.approval_delivery_error = "EMAIL_DELIVERY_FAILED"
        log_event(db, request, "APPROVAL_LINK_DELIVERY_FAILED", project_id=row.project_id, invitation_id=inv.id,
                  metadata={"access_request_id": row.id})
        db.commit()
    return {"ok": True, "state": row.state, "request_id": row.id}

@app.post("/api/admin/access-requests/{access_request_id}/reject")
async def admin_reject_access_request(access_request_id: str, payload: AdminAccessDecision, request: Request,
                                      db: Session = Depends(db_session),
                                      efata_admin_session: str | None = Cookie(default=None),
                                      x_csrf_token: str | None = Header(default=None)):
    verify_admin_csrf(request, x_csrf_token)
    sess = admin_auth(db, efata_admin_session)
    row = db.scalar(select(AccessRequest).where(AccessRequest.id == access_request_id).with_for_update())
    if not row:
        raise HTTPException(404, "Solicitação não encontrada.")
    if row.state != "PENDING_ADMIN_APPROVAL":
        raise HTTPException(409, f"Solicitação já está em estado {row.state}.")
    row.state = "REJECTED"
    row.reviewed_at = now()
    row.reviewed_by = sess.admin_email
    row.review_reason = payload.reason.strip()
    log_event(db, request, "ACCESS_REQUEST_REJECTED", project_id=row.project_id,
              metadata={"access_request_id": row.id, "admin_email": sess.admin_email})
    db.commit()
    try:
        await send_email(
            row.email,
            "Atualização da solicitação de acesso — Efatá",
            "<p>Sua solicitação foi analisada. O acesso não foi liberado neste momento.</p>"
        )
    except Exception:
        pass
    return {"ok": True, "state": row.state, "request_id": row.id}


@app.post("/api/admin/invitations")
async def create_invitation(payload: CreateInvitationRequest, request: Request, db: Session = Depends(db_session),
                            efata_admin_session: str | None = Cookie(default=None), x_csrf_token: str | None = Header(default=None)):
    verify_admin_csrf(request, x_csrf_token)
    admin_auth(db, efata_admin_session)
    project = db.scalar(select(Project).where(Project.slug=="estevez-guarda"))
    raw = random_token(32)
    inv = Invitation(project_id=project.id, token_hash=sha256_text(raw), recipient_email=str(payload.email).lower(),
                     recipient_name=payload.name, organization_name=payload.organization, recipient_role=payload.role,
                     expires_at=expires(days=payload.days_valid))
    db.add(inv); db.commit()
    link = f"{settings.public_base_url.rstrip('/')}/i/{raw}"
    await send_email(inv.recipient_email, "Convite confidencial — Efatá", f"<p>Você recebeu acesso individual ao briefing confidencial do Projeto Estevez.</p><p><a href='{html.escape(link)}'>Acessar portal</a></p><p>Não encaminhe este link.</p>")
    return {"id":inv.id,"link":link,"expires_at":inv.expires_at}

@app.get("/api/admin/overview")
def admin_overview(db: Session = Depends(db_session), efata_admin_session: str | None = Cookie(default=None)):
    admin_auth(db, efata_admin_session)
    invitations = db.scalars(select(Invitation).order_by(desc(Invitation.created_at)).limit(100)).all()
    acceptances = db.scalars(select(LegalAcceptance).order_by(desc(LegalAcceptance.accepted_at)).limit(100)).all()
    events = db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(250)).all()
    access_requests = db.scalars(select(AccessRequest).order_by(desc(AccessRequest.requested_at)).limit(100)).all()
    return {
        "invitations":[{"id":x.id,"email":x.recipient_email,"name":x.recipient_name,"organization":x.organization_name,"expires_at":x.expires_at,"revoked_at":x.revoked_at} for x in invitations],
        "acceptances":[{"id":x.id,"name":x.recipient_name,"email":x.recipient_email,"organization":x.organization_name,"term_version":x.term_version,"accepted_at":x.accepted_at,"access_id":x.access_id} for x in acceptances],
        "access_requests":[{"id":x.id,"full_name":x.full_name,"email":x.email,"organization":x.organization_name,"role":x.recipient_role,"purpose":x.purpose,"state":x.state,"requested_at":x.requested_at,"reviewed_at":x.reviewed_at,"reviewed_by":x.reviewed_by} for x in access_requests],
        "push_enabled": push_available(),
        "events":[{"event_type":x.event_type,"created_at":x.created_at,"invitation_id":x.invitation_id,"acceptance_id":x.acceptance_id,"access_session_id":x.access_session_id,"request_id":x.request_id,"ip_address":x.ip_address,"user_agent":x.user_agent,"metadata":json.loads(x.metadata_json or "{}")} for x in events],
    }

@app.post("/api/admin/invitations/{invitation_id}/revoke")
def revoke_invitation(invitation_id: str, request: Request, db: Session = Depends(db_session),
                      efata_admin_session: str | None = Cookie(default=None), x_csrf_token: str | None = Header(default=None)):
    verify_admin_csrf(request, x_csrf_token)
    admin_auth(db, efata_admin_session)
    inv = db.get(Invitation, invitation_id)
    if not inv: raise HTTPException(404)
    inv.revoked_at=now()
    sessions=db.scalars(select(AccessSession).where(AccessSession.invitation_id==inv.id, AccessSession.revoked_at.is_(None))).all()
    for s in sessions: s.revoked_at=now()
    db.commit()
    return {"ok":True}

@app.get("/api/admin/agent/threads")
def admin_agent_threads(db: Session = Depends(db_session), efata_admin_session: str | None = Cookie(default=None)):
    admin_auth(db, efata_admin_session)
    threads=db.scalars(select(AgentThread).order_by(desc(AgentThread.updated_at)).limit(100)).all()
    out=[]
    for t in threads:
        acc=db.get(LegalAcceptance,t.acceptance_id)
        msgs=db.scalars(select(AgentMessage).where(AgentMessage.thread_id==t.id).order_by(AgentMessage.created_at)).all()
        out.append({"id":t.id,"user":acc.recipient_name if acc else None,"email":acc.recipient_email if acc else None,"updated_at":t.updated_at,
                    "messages":[{"role":m.role,"content":m.content,"sha256":m.content_sha256,"model":m.model,"created_at":m.created_at} for m in msgs]})
    return out

@app.on_event("startup")
def startup():
    if settings.seed_content_on_startup:
        from .seed import seed
        seed()
