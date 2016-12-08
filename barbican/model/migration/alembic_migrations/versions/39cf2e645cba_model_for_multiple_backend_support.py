#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Model for multiple backend support

Revision ID: 39cf2e645cba
Revises: d2780d5aa510
Create Date: 2016-07-29 16:45:22.953811

"""

# revision identifiers, used by Alembic.
revision = '39cf2e645cba'
down_revision = 'd2780d5aa510'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()
    table_exists = ctx.dialect.has_table(con.engine, 'secret_stores')
    if not table_exists:
        op.create_table(
            'secret_stores',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('store_plugin', sa.String(length=255), nullable=False),
            sa.Column('crypto_plugin', sa.String(length=255), nullable=True),
            sa.Column('global_default', sa.Boolean(), nullable=False,
                      default=False),
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('store_plugin', 'crypto_plugin',
                                name='_secret_stores_plugin_names_uc'),
            sa.UniqueConstraint('name',
                                name='_secret_stores_name_uc')
        )

    table_exists = ctx.dialect.has_table(con.engine, 'project_secret_store')
    if not table_exists:
        op.create_table(
            'project_secret_store',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('secret_store_id', sa.String(length=36), nullable=False),
            sa.ForeignKeyConstraint(['project_id'], ['projects.id'],),
            sa.ForeignKeyConstraint(
                ['secret_store_id'], ['secret_stores.id'],),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('project_id',
                                name='_project_secret_store_project_uc')
        )
        op.create_index(op.f('ix_project_secret_store_project_id'),
                        'project_secret_store', ['project_id'], unique=True)
