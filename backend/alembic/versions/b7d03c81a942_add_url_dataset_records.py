"""Add indexed exact URL dataset records."""

from alembic import op
import sqlalchemy as sa


revision = "b7d03c81a942"
down_revision = "f28d9b603a11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "url_dataset_records",
        sa.Column("canonical_hash", sa.String(length=64), nullable=False),
        sa.Column("source_label", sa.String(length=40), nullable=False),
        sa.Column("dataset_name", sa.String(length=255), nullable=False),
        sa.Column("record_source", sa.String(length=255), nullable=True),
        sa.Column("dataset_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("canonical_hash"),
    )
    op.create_index("ix_url_dataset_records_source_label", "url_dataset_records", ["source_label"])
    op.create_index("ix_url_dataset_records_dataset_name", "url_dataset_records", ["dataset_name"])


def downgrade() -> None:
    op.drop_index("ix_url_dataset_records_dataset_name", table_name="url_dataset_records")
    op.drop_index("ix_url_dataset_records_source_label", table_name="url_dataset_records")
    op.drop_table("url_dataset_records")
