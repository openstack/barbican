"""dsa in container type modelbase_to

Revision ID: 2ab3f5371bde
Revises: 4070806f6972
Create Date: 2014-09-02 12:11:43.524247

"""

# revision identifiers, used by Alembic.
revision = '2ab3f5371bde'
down_revision = '4070806f6972'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('container_secret', sa.Column('created_at', sa.DateTime(), nullable=False))
    op.add_column('container_secret', sa.Column('deleted', sa.Boolean(), nullable=False))
    op.add_column('container_secret', sa.Column('deleted_at', sa.DateTime(), nullable=True))
    op.add_column('container_secret', sa.Column('id', sa.String(length=36), nullable=False))
    op.add_column('container_secret', sa.Column('status', sa.String(length=20), nullable=False))
    op.add_column('container_secret', sa.Column('updated_at', sa.DateTime(), nullable=False))

    op.create_primary_key('pk_container_secret', 'container_secret', ['id'])
    op.create_unique_constraint(
        '_container_secret_name_uc',
        'container_secret',
        ['container_id', 'secret_id', 'name']
    )
