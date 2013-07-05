"""create test table

Revision ID: 1a0c2cdafb38
Revises: 40a9c7408b51
Create Date: 2013-06-17 16:42:13.634746

"""

# revision identifiers, used by Alembic.
revision = '1a0c2cdafb38'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'test',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(50), nullable=False),
        sa.Column('description', sa.Unicode(200)),
    )


def downgrade():
    op.drop_table('test')
