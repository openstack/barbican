"""Remove transport keys column from project quotas table

Revision ID: 10220ccbe7fa
Revises: 3c3b04040bfe
Create Date: 2015-09-09 09:10:23.812681

"""

# revision identifiers, used by Alembic.
revision = '10220ccbe7fa'
down_revision = '3c3b04040bfe'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('project_quotas', 'transport_keys')
