"""Super Admin approval access requests + Web Push subscriptions."""
from alembic import op
import sqlalchemy as sa

revision = "002_superadmin_access_requests"
down_revision = "001_secure_briefing"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("invitations", sa.Column("link_consumed_at", sa.DateTime(), nullable=True))

    op.create_table(
        "access_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("organization_name", sa.String(255), nullable=False),
        sa.Column("recipient_role", sa.String(255), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("state", sa.String(40), nullable=False, server_default="PENDING_ADMIN_APPROVAL"),
        sa.Column("request_fingerprint_hash", sa.String(64), nullable=False),
        sa.Column("request_ip", sa.String(128), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by", sa.String(320), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("approved_invitation_id", sa.String(36), sa.ForeignKey("invitations.id"), nullable=True),
        sa.Column("approval_notified_at", sa.DateTime(), nullable=True),
        sa.Column("approval_delivery_error", sa.String(240), nullable=True),
        sa.CheckConstraint(
            "state IN ('PENDING_ADMIN_APPROVAL','APPROVED','REJECTED','CANCELLED','EXPIRED')",
            name="ck_access_request_state"
        ),
    )
    op.create_index("ix_access_request_state_requested","access_requests",["state","requested_at"])
    op.create_index("ix_access_request_email","access_requests",["email"])
    op.create_index("ix_access_request_fingerprint","access_requests",["request_fingerprint_hash","requested_at"])

    op.create_table(
        "push_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("admin_email", sa.String(320), nullable=False),
        sa.Column("endpoint", sa.Text(), nullable=False, unique=True),
        sa.Column("p256dh", sa.Text(), nullable=False),
        sa.Column("auth", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
    )

def downgrade():
    op.drop_table("push_subscriptions")
    op.drop_table("access_requests")
    op.drop_column("invitations", "link_consumed_at")
