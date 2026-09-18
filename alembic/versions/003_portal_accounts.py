"""MVP recurring portal accounts: activation OTP once, then email/password login."""
from alembic import op
import sqlalchemy as sa

revision = "003_portal_accounts"
down_revision = "002_superadmin_access_requests"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "portal_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("invitation_id", sa.String(36), sa.ForeignKey("invitations.id"), nullable=False, unique=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(500), nullable=False),
        sa.Column("state", sa.String(30), nullable=False, server_default="ACTIVE"),
        sa.Column("activated_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("project_id", "email", name="uq_portal_account_project_email"),
        sa.CheckConstraint("state IN ('ACTIVE','SUSPENDED','REVOKED')", name="ck_portal_account_state"),
    )
    op.create_index("ix_portal_account_email_state", "portal_accounts", ["email", "state"])

def downgrade():
    op.drop_index("ix_portal_account_email_state", table_name="portal_accounts")
    op.drop_table("portal_accounts")
