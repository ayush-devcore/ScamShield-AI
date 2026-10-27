"""add MFA and server-managed sessions

Revision ID: a8c82d7e3112
Revises: eeb5e5c5b00d
"""
from alembic import op
import sqlalchemy as sa

revision = "a8c82d7e3112"
down_revision = "eeb5e5c5b00d"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("user_mfa", sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True), sa.Column("secret_encrypted", sa.Text()), sa.Column("pending_secret_encrypted", sa.Text()), sa.Column("enabled_at", sa.DateTime(timezone=True)))
    op.create_table("user_sessions", sa.Column("id", sa.UUID(), primary_key=True), sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("user_agent", sa.String(255)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])
    op.create_index("ix_user_sessions_revoked_at", "user_sessions", ["revoked_at"])
    op.create_table("recovery_codes", sa.Column("id", sa.UUID(), primary_key=True), sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("code_hash", sa.String(255), nullable=False, unique=True), sa.Column("used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])

def downgrade():
    op.drop_index("ix_recovery_codes_user_id", table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_index("ix_user_sessions_revoked_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_table("user_mfa")
