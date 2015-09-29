"""Made plugin names in kek datum non nullable

Revision ID: 47b69e523451
Revises: cd4106a1a0
Create Date: 2014-06-16 14:05:45.428226

"""

# revision identifiers, used by Alembic.
revision = '47b69e523451'
down_revision = 'cd4106a1a0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('kek_data', 'plugin_name',
                    type_=sa.String(255), nullable=False)
