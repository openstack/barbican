"""Add project quotas table

Revision ID: 46b98cde536
Revises: 1bece815014f
Create Date: 2015-08-28 17:42:35.057103

"""

# revision identifiers, used by Alembic.
revision = '46b98cde536'
down_revision = 'kilo'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()
    table_exists = ctx.dialect.has_table(con.engine, 'project_quotas')
    if not table_exists:
        op.create_table(
            'project_quotas',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('secrets', sa.Integer(), nullable=True),
            sa.Column('orders', sa.Integer(), nullable=True),
            sa.Column('containers', sa.Integer(), nullable=True),
            sa.Column('transport_keys', sa.Integer(), nullable=True),
            sa.Column('consumers', sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(['project_id'],
                                    ['projects.id'],
                                    name='project_quotas_fk'),
            sa.PrimaryKeyConstraint('id'),
            mysql_engine='InnoDB')
        op.create_index(
            op.f('ix_project_quotas_project_id'),
            'project_quotas',
            ['project_id'],
            unique=False)
