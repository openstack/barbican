"""Add OrderRetryTask

Revision ID: aa2cf96a1d5
Revises: 256da65e0c5f
Create Date: 2015-01-19 10:27:19.179196

"""

# revision identifiers, used by Alembic.
revision = "aa2cf96a1d5"
down_revision = "256da65e0c5f"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        "order_retry_tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("order_id", sa.String(length=36), nullable=False),
        sa.Column("retry_task", sa.Text(), nullable=False),
        sa.Column("retry_at", sa.DateTime(), nullable=False),
        sa.Column("retry_args", sa.Text(), nullable=False),
        sa.Column("retry_kwargs", sa.Text(), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["order_id"], ["orders.id"]),
        sa.PrimaryKeyConstraint("id"),
        mysql_engine="InnoDB"
    )
