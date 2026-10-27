"""Add durable, encrypted-target sandbox jobs."""

from alembic import op
import sqlalchemy as sa


revision = "f28d9b603a11"
down_revision = "d44aa39b2781"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_jobs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("target_encrypted", sa.Text(), nullable=True),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("observations", sa.JSON(), nullable=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_sandbox_jobs_scan_id", "sandbox_jobs", ["scan_id"])
    op.create_index("ix_sandbox_jobs_state", "sandbox_jobs", ["state"])


def downgrade() -> None:
    op.drop_index("ix_sandbox_jobs_state", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_scan_id", table_name="sandbox_jobs")
    op.drop_table("sandbox_jobs")
