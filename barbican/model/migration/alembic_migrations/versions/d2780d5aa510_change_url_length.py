"""change_url_length

Revision ID: d2780d5aa510
Revises: dce488646127
Create Date: 2016-03-11 09:39:32.593231

"""

# revision identifiers, used by Alembic.
revision = 'd2780d5aa510'
down_revision = 'dce488646127'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        'container_consumer_metadata',
        'URL',
        type_=sa.String(length=255)
    )
