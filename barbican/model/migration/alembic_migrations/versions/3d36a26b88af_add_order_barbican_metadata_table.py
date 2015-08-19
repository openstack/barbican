"""Add OrderBarbicanMetadata table

Revision ID: 3d36a26b88af
Revises: 443d6f4a69ac
Create Date: 2015-02-20 12:27:08.155647

"""

# revision identifiers, used by Alembic.
revision = '3d36a26b88af'
down_revision = '443d6f4a69ac'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()
    table_exists = ctx.dialect.has_table(con.engine, 'order_barbican_metadata')
    if not table_exists:
        op.create_table(
            'order_barbican_metadata',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('order_id', sa.String(length=36), nullable=False),
            sa.Column('key', sa.String(length=255), nullable=False),
            sa.Column('value', sa.String(length=255), nullable=False),
            sa.ForeignKeyConstraint(['order_id'], ['orders.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
