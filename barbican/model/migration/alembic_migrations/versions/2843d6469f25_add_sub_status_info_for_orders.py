"""add sub status info for orders

Revision ID: 2843d6469f25
Revises: 2ab3f5371bde
Create Date: 2014-09-16 12:31:15.181380

"""

# revision identifiers, used by Alembic.
revision = '2843d6469f25'
down_revision = '2ab3f5371bde'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('orders', sa.Column('sub_status', sa.String(length=36), nullable=True))
    op.add_column('orders', sa.Column('sub_status_message', sa.String(length=255), nullable=True))
