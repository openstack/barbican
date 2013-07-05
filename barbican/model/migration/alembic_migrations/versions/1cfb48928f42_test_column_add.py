"""test column add

Revision ID: 1cfb48928f42
Revises: 153ed0150d78
Create Date: 2013-06-19 00:15:03.656628

"""

# revision identifiers, used by Alembic.
revision = '1cfb48928f42'
down_revision = '153ed0150d78'

from alembic import op
from sqlalchemy import Column, String


def upgrade():
    op.add_column('secrets', Column('dummy_column', String()))


def downgrade():
    op.drop_column('secrets', 'dummy_column')
