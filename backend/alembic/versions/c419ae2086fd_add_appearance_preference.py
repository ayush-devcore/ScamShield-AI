"""Add per-user appearance preference."""

from alembic import op
import sqlalchemy as sa


revision = "c419ae2086fd"
down_revision = "a8c82d7e3112"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_preferences",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("appearance", sa.String(length=10), server_default="dark", nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )


def downgrade() -> None:
    op.drop_table("user_preferences")
