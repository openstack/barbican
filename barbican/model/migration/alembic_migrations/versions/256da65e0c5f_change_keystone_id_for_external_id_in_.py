"""Change keystone_id for external_id in Project model

Revision ID: 256da65e0c5f
Revises: 795737bb3c3
Create Date: 2014-12-22 03:55:29.072375

"""

# revision identifiers, used by Alembic.
revision = '256da65e0c5f'
down_revision = '795737bb3c3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('projects', 'keystone_id',
                    type_=sa.String(36),
                    new_column_name='external_id')
