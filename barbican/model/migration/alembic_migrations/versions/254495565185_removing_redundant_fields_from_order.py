"""removing redundant fields from order

Revision ID: 254495565185
Revises: 2843d6469f25
Create Date: 2014-09-16 12:09:23.716390

"""

# revision identifiers, used by Alembic.
revision = '254495565185'
down_revision = '2843d6469f25'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('orders', 'secret_mode')
    op.drop_column('orders', 'secret_algorithm')
    op.drop_column('orders', 'secret_bit_length')
    op.drop_column('orders', 'secret_expiration')
    op.drop_column('orders', 'secret_payload_content_type')
    op.drop_column('orders', 'secret_name')
