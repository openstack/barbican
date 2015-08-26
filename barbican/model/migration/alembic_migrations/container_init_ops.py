# Copyright 2015 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

# Initial operations for agent management extension
# This module only manages the 'agents' table. Binding tables are created
# in the modules for relevant resources


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'containers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('type', sa.Enum('generic', 'rsa', 'dsa', 'certificate',
                                  name='container_types'), nullable=True),
        sa.Column('creator_id', sa.String(length=255), nullable=True),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'],),
        sa.PrimaryKeyConstraint('id')
    )

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
        sa.ForeignKeyConstraint(['acl_id'], ['container_acls.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('acl_id', 'user_id',
                            name='_container_acl_user_uc')
    )
    op.create_index(op.f('ix_container_acl_users_acl_id'),
                    'container_acl_users', ['acl_id'], unique=False)

    op.create_table(
        'container_consumer_metadata',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('container_id', sa.String(length=36), nullable=False),
        sa.Column('URL', sa.String(length=500), nullable=True),
        sa.Column('data_hash', sa.CHAR(64), nullable=True),
        sa.ForeignKeyConstraint(['container_id'], ['containers.id'],),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('data_hash',
                            name='_consumer_hashed_container_name_url_uc'),
        sa.Index('values_index', 'container_id', 'name', 'URL')
    )

    op.create_table(
        'container_secret',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('container_id', sa.String(length=36), nullable=False),
        sa.Column('secret_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['container_id'], ['containers.id'],),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'],),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('container_id', 'secret_id', 'name',
                            name='_container_secret_name_uc')
    )
