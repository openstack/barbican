"""Remove size limits on meta table values

Revision ID: 3041b53b95d7
Revises: 1a7cf79559e3
Create Date: 2015-04-08 15:43:32.852529

"""

# revision identifiers, used by Alembic.
revision = '3041b53b95d7'
down_revision = '1a7cf79559e3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        'order_barbican_metadata',
        'value',
        type_=sa.Text()
    )

    op.alter_column(
        'certificate_authority_metadata',
        'value',
        type_=sa.Text()
    )
