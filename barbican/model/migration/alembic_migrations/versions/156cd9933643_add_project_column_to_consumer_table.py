"""Add project column to consumer table

Revision ID: 156cd9933643
Revises: 46b98cde536
Create Date: 2015-08-28 20:53:23.205128

"""

# revision identifiers, used by Alembic.
revision = '156cd9933643'
down_revision = '46b98cde536'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'container_consumer_metadata',
        sa.Column('project_id',
        sa.String(length=36),
        nullable=True))
    op.create_index(
        op.f('ix_container_consumer_metadata_project_id'),
        'container_consumer_metadata',
        ['project_id'],
        unique=False)
    op.create_foreign_key(
        None,
        'container_consumer_metadata',
        'projects',
        ['project_id'],
        ['id'])
