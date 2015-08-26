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
        'secrets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('secret_type', sa.String(length=255), nullable=True),
        sa.Column('expiration', sa.DateTime(), nullable=True),
        sa.Column('algorithm', sa.String(length=255), nullable=True),
        sa.Column('bit_length', sa.Integer(), nullable=True),
        sa.Column('mode', sa.String(length=255), nullable=True),
        sa.Column('creator_id', sa.String(length=255), nullable=True),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'],
                                'secrets_project_fk'),
        sa.PrimaryKeyConstraint('id')
    )

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

    op.create_table(
        'secret_store_metadata',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('secret_id', sa.String(length=36), nullable=False),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'],),
        sa.PrimaryKeyConstraint('id')
    )
