"""Test auto migration

Revision ID: 40a9c7408b51
Revises: None
Create Date: 2013-06-17 10:42:20.078204

"""

# revision identifiers, used by Alembic.
revision = '40a9c7408b51'
down_revision = '1a0c2cdafb38'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('test', u'name',
                    existing_type=sa.String(50),
                    nullable=True)


def downgrade():
    op.alter_column('test', u'name',
                    existing_type=sa.String(50),
                    nullable=False)
