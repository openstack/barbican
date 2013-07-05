"""change test column back to not null

Revision ID: 153ed0150d78
Revises: 40a9c7408b51
Create Date: 2013-06-18 17:33:20.281076

"""

# revision identifiers, used by Alembic.
revision = '153ed0150d78'
down_revision = '40a9c7408b51'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('test', u'name',
                    existing_type=sa.String(50),
                    nullable=False)


def downgrade():
    op.alter_column('test', u'name',
                    existing_type=sa.String(50),
                    nullable=True)
