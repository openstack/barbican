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
        'orders',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('error_status_code', sa.String(length=16), nullable=True),
        sa.Column('error_reason', sa.String(length=255), nullable=True),
        sa.Column('secret_id', sa.String(length=36), nullable=True),
        sa.Column('secret_mode', sa.String(length=255), nullable=True),
        sa.Column('secret_algorithm', sa.String(length=255), nullable=True),
        sa.Column('secret_bit_length', sa.String(length=255), nullable=True),
        sa.Column('secret_expiration', sa.String(length=255), nullable=True),
        sa.Column('secret_payload_content_type', sa.String(length=255),
                  nullable=True),
        sa.Column('secret_name', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
