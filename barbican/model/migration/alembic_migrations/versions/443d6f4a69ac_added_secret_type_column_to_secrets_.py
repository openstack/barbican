"""added secret type column to secrets table

Revision ID: 443d6f4a69ac
Revises: aa2cf96a1d5
Create Date: 2015-02-16 12:35:12.876413

"""

# revision identifiers, used by Alembic.
revision = '443d6f4a69ac'
down_revision = 'aa2cf96a1d5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('secrets', sa.Column('secret_type', sa.String(length=255),
                  nullable=False, server_default="opaque"))
