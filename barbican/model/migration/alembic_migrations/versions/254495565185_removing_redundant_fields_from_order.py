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


def downgrade():
    op.add_column('orders', sa.Column('secret_name', sa.String(length=255),
                                      nullable=True))
    op.add_column('orders', sa.Column('secret_payload_content_type',
                                      sa.String(length=255),
                                      nullable=True))
    op.add_column('orders', sa.Column('secret_expiration',
                                      sa.DateTime(), nullable=True))
    op.add_column('orders', sa.Column('secret_bit_length',
                                      sa.Integer(),
                                      autoincrement=False,
                                      nullable=True))
    op.add_column('orders', sa.Column('secret_algorithm',
                                      sa.String(length=255),
                                      nullable=True))
    op.add_column('orders', sa.Column('secret_mode', sa.String(length=255),
                                      nullable=True))
