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
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'],),
        sa.PrimaryKeyConstraint('id')
    )

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
        sa.Column('URL', sa.String(length=255), nullable=True),
        sa.Column('data_hash', sa.CHAR(64), nullable=True),
        sa.ForeignKeyConstraint(['container_id'], ['containers.id'],),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('data_hash',
                            name='_consumer_hashed_container_name_url_uc'),
        sa.Index('values_index', 'container_id', 'name', 'URL')
    )

    op.create_table(
        'container_secret',
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('container_id', sa.String(length=36), nullable=False),
        sa.Column('secret_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['container_id'], ['containers.id'],),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'],)
    )
