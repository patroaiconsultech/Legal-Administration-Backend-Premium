import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Integer, Boolean, ForeignKey, UniqueConstraint, Index, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def uid():
    return str(uuid.uuid4())

def utcnow():
    return datetime.utcnow()

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class LegalTerm(Base):
    __tablename__ = "legal_terms"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    document_storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    privacy_storage_key: Mapped[str | None] = mapped_column(String(500))
    published_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime)
    requires_reacceptance: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("project_id", "version", name="uq_legal_term_project_version"),)

class Invitation(Base):
    __tablename__ = "invitations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    recipient_email: Mapped[str] = mapped_column(String(320), nullable=False)
    recipient_name: Mapped[str | None] = mapped_column(String(255))
    organization_name: Mapped[str] = mapped_column(String(255), default="Estevez Guarda Administração Judicial Ltda.")
    recipient_role: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    link_consumed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class OTPChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    subject_type: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(50), nullable=False)
    otp_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime)
    __table_args__ = (Index("ix_otp_subject_purpose", "subject_type", "subject_id", "purpose"),)

class LegalAcceptance(Base):
    __tablename__ = "legal_acceptances"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    evidence_id: Mapped[str] = mapped_column(String(36), unique=True, default=uid, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    term_id: Mapped[str] = mapped_column(ForeignKey("legal_terms.id"), nullable=False)
    invitation_id: Mapped[str] = mapped_column(ForeignKey("invitations.id"), nullable=False)
    term_version: Mapped[str] = mapped_column(String(50), nullable=False)
    term_document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_name: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient_email: Mapped[str] = mapped_column(String(320), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient_role: Mapped[str] = mapped_column(String(255), nullable=False)
    representation_mode: Mapped[str] = mapped_column(String(50), nullable=False)
    representation_declaration: Mapped[str | None] = mapped_column(Text)
    authentication_method: Mapped[str] = mapped_column(String(50), default="ADMIN_APPROVED_MAGIC_LINK", nullable=False)
    email_verified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(128))
    user_agent: Mapped[str | None] = mapped_column(Text)
    access_id: Mapped[str] = mapped_column(String(36), default=uid, unique=True, nullable=False)
    acceptance_text_version: Mapped[str] = mapped_column(String(50), default="1.0", nullable=False)
    receipt_storage_key: Mapped[str | None] = mapped_column(String(500))
    receipt_sha256: Mapped[str | None] = mapped_column(String(64))
    evidence_created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class PortalAccount(Base):
    __tablename__ = "portal_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    invitation_id: Mapped[str] = mapped_column(ForeignKey("invitations.id"), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    state: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint("project_id", "email", name="uq_portal_account_project_email"),
        CheckConstraint("state IN ('ACTIVE','SUSPENDED','REVOKED')", name="ck_portal_account_state"),
        Index("ix_portal_account_email_state", "email", "state"),
    )

class AccessSession(Base):
    __tablename__ = "access_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    invitation_id: Mapped[str] = mapped_column(ForeignKey("invitations.id"), nullable=False)
    acceptance_id: Mapped[str | None] = mapped_column(ForeignKey("legal_acceptances.id"))
    session_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email_verified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"))
    invitation_id: Mapped[str | None] = mapped_column(ForeignKey("invitations.id"))
    acceptance_id: Mapped[str | None] = mapped_column(ForeignKey("legal_acceptances.id"))
    access_session_id: Mapped[str | None] = mapped_column(ForeignKey("access_sessions.id"))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(128))
    user_agent: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_audit_event_created", "created_at"), Index("ix_audit_event_type", "event_type"),)

class AdminSession(Base):
    __tablename__ = "admin_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    admin_email: Mapped[str] = mapped_column(String(320), nullable=False)
    session_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class AgentThread(Base):
    __tablename__ = "agent_threads"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    invitation_id: Mapped[str] = mapped_column(ForeignKey("invitations.id"), nullable=False)
    acceptance_id: Mapped[str] = mapped_column(ForeignKey("legal_acceptances.id"), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class AgentMessage(Base):
    __tablename__ = "agent_messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    thread_id: Mapped[str] = mapped_column(ForeignKey("agent_threads.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str | None] = mapped_column(String(100))
    sources_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient_role: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(40), default="PENDING_ADMIN_APPROVAL", nullable=False)
    request_fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_ip: Mapped[str | None] = mapped_column(String(128))
    user_agent: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    reviewed_by: Mapped[str | None] = mapped_column(String(320))
    review_reason: Mapped[str | None] = mapped_column(Text)
    approved_invitation_id: Mapped[str | None] = mapped_column(ForeignKey("invitations.id"))
    approval_notified_at: Mapped[datetime | None] = mapped_column(DateTime)
    approval_delivery_error: Mapped[str | None] = mapped_column(String(240))
    __table_args__ = (
        Index("ix_access_request_state_requested", "state", "requested_at"),
        Index("ix_access_request_email", "email"),
        Index("ix_access_request_fingerprint", "request_fingerprint_hash", "requested_at"),
    )

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    admin_email: Mapped[str] = mapped_column(String(320), nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    p256dh: Mapped[str] = mapped_column(Text, nullable=False)
    auth: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
