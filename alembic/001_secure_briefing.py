"""Initial Secure Briefing Portal schema."""
from alembic import op
import sqlalchemy as sa
revision = "001_secure_briefing"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("projects",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("slug",sa.String(120),nullable=False,unique=True),
        sa.Column("name",sa.String(255),nullable=False), sa.Column("active",sa.Boolean(),nullable=False),
        sa.Column("created_at",sa.DateTime(),nullable=False))
    op.create_table("legal_terms",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("project_id",sa.String(36),sa.ForeignKey("projects.id"),nullable=False),
        sa.Column("name",sa.String(255),nullable=False), sa.Column("version",sa.String(50),nullable=False),
        sa.Column("document_sha256",sa.String(64),nullable=False), sa.Column("document_storage_key",sa.String(500),nullable=False),
        sa.Column("privacy_storage_key",sa.String(500)), sa.Column("published_at",sa.DateTime(),nullable=False),
        sa.Column("effective_at",sa.DateTime(),nullable=False), sa.Column("superseded_at",sa.DateTime()),
        sa.Column("requires_reacceptance",sa.Boolean(),nullable=False), sa.Column("created_at",sa.DateTime(),nullable=False),
        sa.UniqueConstraint("project_id","version",name="uq_legal_term_project_version"))
    op.create_table("invitations",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("project_id",sa.String(36),sa.ForeignKey("projects.id"),nullable=False),
        sa.Column("token_hash",sa.String(64),nullable=False,unique=True), sa.Column("recipient_email",sa.String(320),nullable=False),
        sa.Column("recipient_name",sa.String(255)), sa.Column("organization_name",sa.String(255),nullable=False),
        sa.Column("recipient_role",sa.String(255)), sa.Column("expires_at",sa.DateTime(),nullable=False),
        sa.Column("revoked_at",sa.DateTime()), sa.Column("email_verified_at",sa.DateTime()), sa.Column("created_at",sa.DateTime(),nullable=False))
    op.create_table("otp_challenges",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("subject_type",sa.String(30),nullable=False),
        sa.Column("subject_id",sa.String(255),nullable=False), sa.Column("purpose",sa.String(50),nullable=False),
        sa.Column("otp_hash",sa.String(64),nullable=False), sa.Column("issued_at",sa.DateTime(),nullable=False),
        sa.Column("expires_at",sa.DateTime(),nullable=False), sa.Column("validated_at",sa.DateTime()),
        sa.Column("attempt_count",sa.Integer(),nullable=False), sa.Column("invalidated_at",sa.DateTime()))
    op.create_index("ix_otp_subject_purpose","otp_challenges",["subject_type","subject_id","purpose"])
    op.create_table("legal_acceptances",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("evidence_id",sa.String(36),nullable=False,unique=True),
        sa.Column("project_id",sa.String(36),sa.ForeignKey("projects.id"),nullable=False),
        sa.Column("term_id",sa.String(36),sa.ForeignKey("legal_terms.id"),nullable=False),
        sa.Column("invitation_id",sa.String(36),sa.ForeignKey("invitations.id"),nullable=False),
        sa.Column("term_version",sa.String(50),nullable=False), sa.Column("term_document_sha256",sa.String(64),nullable=False),
        sa.Column("recipient_name",sa.String(255),nullable=False), sa.Column("recipient_email",sa.String(320),nullable=False),
        sa.Column("organization_name",sa.String(255),nullable=False), sa.Column("recipient_role",sa.String(255),nullable=False),
        sa.Column("representation_mode",sa.String(50),nullable=False), sa.Column("representation_declaration",sa.Text()),
        sa.Column("authentication_method",sa.String(50),nullable=False), sa.Column("email_verified_at",sa.DateTime(),nullable=False),
        sa.Column("accepted_at",sa.DateTime(),nullable=False), sa.Column("timezone",sa.String(100),nullable=False),
        sa.Column("ip_address",sa.String(128)), sa.Column("user_agent",sa.Text()), sa.Column("access_id",sa.String(36),nullable=False,unique=True),
        sa.Column("acceptance_text_version",sa.String(50),nullable=False), sa.Column("receipt_storage_key",sa.String(500)),
        sa.Column("receipt_sha256",sa.String(64)), sa.Column("evidence_created_at",sa.DateTime(),nullable=False))
    op.create_table("access_sessions",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("invitation_id",sa.String(36),sa.ForeignKey("invitations.id"),nullable=False),
        sa.Column("acceptance_id",sa.String(36),sa.ForeignKey("legal_acceptances.id")), sa.Column("session_token_hash",sa.String(64),nullable=False,unique=True),
        sa.Column("email_verified_at",sa.DateTime(),nullable=False), sa.Column("authorized_at",sa.DateTime()),
        sa.Column("expires_at",sa.DateTime(),nullable=False), sa.Column("revoked_at",sa.DateTime()), sa.Column("created_at",sa.DateTime(),nullable=False))
    op.create_table("audit_events",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("project_id",sa.String(36),sa.ForeignKey("projects.id")),
        sa.Column("invitation_id",sa.String(36),sa.ForeignKey("invitations.id")), sa.Column("acceptance_id",sa.String(36),sa.ForeignKey("legal_acceptances.id")),
        sa.Column("access_session_id",sa.String(36),sa.ForeignKey("access_sessions.id")), sa.Column("event_type",sa.String(100),nullable=False),
        sa.Column("request_id",sa.String(64),nullable=False), sa.Column("ip_address",sa.String(128)), sa.Column("user_agent",sa.Text()),
        sa.Column("metadata_json",sa.Text()), sa.Column("created_at",sa.DateTime(),nullable=False))
    op.create_index("ix_audit_event_created","audit_events",["created_at"])
    op.create_index("ix_audit_event_type","audit_events",["event_type"])
    op.create_table("admin_sessions",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("admin_email",sa.String(320),nullable=False),
        sa.Column("session_token_hash",sa.String(64),nullable=False,unique=True), sa.Column("expires_at",sa.DateTime(),nullable=False),
        sa.Column("revoked_at",sa.DateTime()), sa.Column("created_at",sa.DateTime(),nullable=False))
    op.create_table("agent_threads",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("project_id",sa.String(36),sa.ForeignKey("projects.id"),nullable=False),
        sa.Column("invitation_id",sa.String(36),sa.ForeignKey("invitations.id"),nullable=False),
        sa.Column("acceptance_id",sa.String(36),sa.ForeignKey("legal_acceptances.id"),nullable=False),
        sa.Column("title",sa.String(255)), sa.Column("created_at",sa.DateTime(),nullable=False), sa.Column("updated_at",sa.DateTime(),nullable=False))
    op.create_table("agent_messages",
        sa.Column("id",sa.String(36),primary_key=True), sa.Column("thread_id",sa.String(36),sa.ForeignKey("agent_threads.id"),nullable=False),
        sa.Column("role",sa.String(20),nullable=False), sa.Column("content",sa.Text()), sa.Column("content_sha256",sa.String(64),nullable=False),
        sa.Column("model",sa.String(100)), sa.Column("sources_json",sa.Text()), sa.Column("created_at",sa.DateTime(),nullable=False))

def downgrade():
    for table in ["agent_messages","agent_threads","admin_sessions","audit_events","access_sessions","legal_acceptances","otp_challenges","invitations","legal_terms","projects"]:
        op.drop_table(table)
