"""Added CA related tables

Revision ID: 2d21598e7e70
Revises: 3d36a26b88af
Create Date: 2015-03-11 15:47:32.292944

"""

# revision identifiers, used by Alembic.
revision = '2d21598e7e70'
down_revision = '3d36a26b88af'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()

    table_exists = ctx.dialect.has_table(con.engine, 'certificate_authorities')
    if not table_exists:
        op.create_table(
            'certificate_authorities',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('plugin_name', sa.String(length=255), nullable=False),
            sa.Column('plugin_ca_id', sa.Text(), nullable=False),
            sa.Column('expiration', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )

    table_exists = ctx.dialect.has_table(
        con.engine,
        'project_certificate_authorities')
    if not table_exists:
        op.create_table(
            'project_certificate_authorities',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('ca_id', sa.String(length=36), nullable=False),
            sa.ForeignKeyConstraint(['ca_id'], ['certificate_authorities.id'],),
            sa.ForeignKeyConstraint(['project_id'], ['projects.id'],),
            sa.PrimaryKeyConstraint('id', 'project_id', 'ca_id'),
            sa.UniqueConstraint('project_id',
                                'ca_id',
                                name='_project_certificate_authority_uc')
        )

    table_exists = ctx.dialect.has_table(
        con.engine,
        'certificate_authority_metadata')
    if not table_exists:
        op.create_table(
            'certificate_authority_metadata',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('key', sa.String(length=255), nullable=False),
            sa.Column('value', sa.String(length=255), nullable=False),
            sa.Column('ca_id', sa.String(length=36), nullable=False),
            sa.ForeignKeyConstraint(['ca_id'], ['certificate_authorities.id'],),
            sa.PrimaryKeyConstraint('id', 'key', 'ca_id'),
            sa.UniqueConstraint('ca_id',
                                'key',
                                name='_certificate_authority_metadatum_uc')
        )

    table_exists = ctx.dialect.has_table(
        con.engine,
        'preferred_certificate_authorities')

    if not table_exists:
        op.create_table(
            'preferred_certificate_authorities',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('ca_id', sa.String(length=36), nullable=True),
            sa.ForeignKeyConstraint(['ca_id'], ['certificate_authorities.id'],),
            sa.ForeignKeyConstraint(['project_id'], ['projects.id'],),
            sa.PrimaryKeyConstraint('id', 'project_id'),
            sa.UniqueConstraint('project_id')
        )
