"""Proposal documents and version-bound electronic acceptances."""
from alembic import op
import sqlalchemy as sa

revision = "004_proposal_acceptances"
down_revision = "003_portal_accounts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "proposal_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("version", sa.String(80), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.Column("document_storage_key", sa.String(500), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("superseded_at", sa.DateTime(), nullable=True),
        sa.Column("published_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("project_id", "version", name="uq_proposal_project_version"),
    )
    op.create_index(
        "ix_proposal_project_published",
        "proposal_documents",
        ["project_id", "published_at"],
    )

    op.create_table(
        "proposal_acceptances",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False, unique=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("proposal_documents.id"), nullable=False),
        sa.Column("invitation_id", sa.String(36), sa.ForeignKey("invitations.id"), nullable=False),
        sa.Column("account_id", sa.String(36), sa.ForeignKey("portal_accounts.id"), nullable=False),
        sa.Column("proposal_version", sa.String(80), nullable=False),
        sa.Column("proposal_sha256", sa.String(64), nullable=False),
        sa.Column("acceptance_text_version", sa.String(50), nullable=False),
        sa.Column("acceptance_text_sha256", sa.String(64), nullable=False),
        sa.Column("recipient_name", sa.String(255), nullable=False),
        sa.Column("recipient_email", sa.String(320), nullable=False),
        sa.Column("organization_name", sa.String(255), nullable=False),
        sa.Column("recipient_role", sa.String(255), nullable=False),
        sa.Column("representation_mode", sa.String(50), nullable=False),
        sa.Column("representation_declaration", sa.Text(), nullable=True),
        sa.Column("authentication_method", sa.String(80), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False),
        sa.Column("ip_address", sa.String(128), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("access_id", sa.String(36), nullable=False, unique=True),
        sa.Column("receipt_storage_key", sa.String(500), nullable=True),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column("evidence_created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "proposal_id",
            "invitation_id",
            name="uq_proposal_acceptance_invitation",
        ),
    )
    op.create_index(
        "ix_proposal_acceptance_proposal",
        "proposal_acceptances",
        ["proposal_id", "accepted_at"],
    )
    op.create_index(
        "ix_proposal_acceptance_invitation",
        "proposal_acceptances",
        ["invitation_id", "accepted_at"],
    )


def downgrade():
    op.drop_index("ix_proposal_acceptance_invitation", table_name="proposal_acceptances")
    op.drop_index("ix_proposal_acceptance_proposal", table_name="proposal_acceptances")
    op.drop_table("proposal_acceptances")
    op.drop_index("ix_proposal_project_published", table_name="proposal_documents")
    op.drop_table("proposal_documents")
