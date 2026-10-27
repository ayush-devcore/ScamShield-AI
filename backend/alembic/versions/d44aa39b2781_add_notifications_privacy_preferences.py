"""Add user notification and scan-history preferences."""

from alembic import op
import sqlalchemy as sa


revision = "d44aa39b2781"
down_revision = "c419ae2086fd"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user_preferences", sa.Column("store_scan_history", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.add_column("user_preferences", sa.Column("notify_high_risk", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.add_column("user_preferences", sa.Column("notify_critical_risk", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.add_column("user_preferences", sa.Column("notify_security_events", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.create_table(
        "user_notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=140), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("link_path", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", name="uq_user_notifications_scan_id"),
    )
    op.create_index("ix_user_notifications_user_id", "user_notifications", ["user_id"])
    op.create_index("ix_user_notifications_created_at", "user_notifications", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_user_notifications_created_at", table_name="user_notifications")
    op.drop_index("ix_user_notifications_user_id", table_name="user_notifications")
    op.drop_table("user_notifications")
    op.drop_column("user_preferences", "notify_security_events")
    op.drop_column("user_preferences", "notify_critical_risk")
    op.drop_column("user_preferences", "notify_high_risk")
    op.drop_column("user_preferences", "store_scan_history")
