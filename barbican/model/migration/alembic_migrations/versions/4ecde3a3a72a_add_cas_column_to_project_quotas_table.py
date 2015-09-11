"""Add cas column to project quotas table

Revision ID: 4ecde3a3a72a
Revises: 10220ccbe7fa
Create Date: 2015-09-09 09:40:08.540064

"""

# revision identifiers, used by Alembic.
revision = '4ecde3a3a72a'
down_revision = '10220ccbe7fa'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'project_quotas',
        sa.Column('cas', sa.Integer(), nullable=True))
