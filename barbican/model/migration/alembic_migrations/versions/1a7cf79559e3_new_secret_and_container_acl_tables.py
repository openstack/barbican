"""New secret and container ACL tables

Revision ID: 1a7cf79559e3
Revises: 1c0f328bfce0
Create Date: 2015-04-01 13:31:04.292754

"""

# revision identifiers, used by Alembic.
revision = '1a7cf79559e3'
down_revision = '1c0f328bfce0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()
    table_exists = ctx.dialect.has_table(con.engine, 'secret_acls')
    if not table_exists:
        op.create_table(
            'secret_acls',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('secret_id', sa.String(length=36), nullable=False),
            sa.Column('operation', sa.String(length=255), nullable=False),
            sa.Column('creator_only', sa.Boolean(), nullable=False),
            sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'],),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('secret_id', 'operation',
                                name='_secret_acl_operation_uc')
        )
        op.create_index(op.f('ix_secret_acls_secret_id'), 'secret_acls',
                        ['secret_id'], unique=False)

    table_exists = ctx.dialect.has_table(con.engine, 'container_acls')
    if not table_exists:
        op.create_table(
            'container_acls',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('container_id', sa.String(length=36), nullable=False),
            sa.Column('operation', sa.String(length=255), nullable=False),
            sa.Column('creator_only', sa.Boolean(), nullable=False),
            sa.ForeignKeyConstraint(['container_id'], ['containers.id'],),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('container_id', 'operation',
                                name='_container_acl_operation_uc')
        )
        op.create_index(op.f('ix_container_acls_container_id'),
                        'container_acls', ['container_id'], unique=False)
    table_exists = ctx.dialect.has_table(con.engine, 'secret_acl_users')
    if not table_exists:
        op.create_table(
            'secret_acl_users',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('acl_id', sa.String(length=36), nullable=False),
            sa.Column('user_id', sa.String(length=255), nullable=False),
            sa.ForeignKeyConstraint(['acl_id'], ['secret_acls.id'],),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('acl_id', 'user_id',
                                name='_secret_acl_user_uc')
        )
        op.create_index(op.f('ix_secret_acl_users_acl_id'), 'secret_acl_users',
                        ['acl_id'], unique=False)
    table_exists = ctx.dialect.has_table(con.engine, 'container_acl_users')
    if not table_exists:
        op.create_table(
            'container_acl_users',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('acl_id', sa.String(length=36), nullable=False),
            sa.Column('user_id', sa.String(length=255), nullable=False),
            sa.ForeignKeyConstraint(['acl_id'], ['container_acls.id'],),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('acl_id', 'user_id',
                                name='_container_acl_user_uc')
        )
        op.create_index(op.f('ix_container_acl_users_acl_id'),
                        'container_acl_users', ['acl_id'], unique=False)

    op.add_column(u'containers', sa.Column('creator_id', sa.String(length=255),
                                           nullable=True))
    op.add_column(u'orders', sa.Column('creator_id', sa.String(length=255),
                                       nullable=True))
    op.add_column(u'secrets', sa.Column('creator_id', sa.String(length=255),
                                        nullable=True))
