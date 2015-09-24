"""add-cert-to-container-type

Revision ID: cd4106a1a0
Revises: 1e86c18af2dd
Create Date: 2014-06-10 15:07:25.084173

"""

# revision identifiers, used by Alembic.
revision = 'cd4106a1a0'
down_revision = '1e86c18af2dd'

from alembic import op
import sqlalchemy as sa


def upgrade():
    enum_type = sa.Enum(
        'generic', 'rsa', 'dsa', 'certificate',
        name='container_types')
    op.alter_column('containers', 'type', type_=enum_type)
