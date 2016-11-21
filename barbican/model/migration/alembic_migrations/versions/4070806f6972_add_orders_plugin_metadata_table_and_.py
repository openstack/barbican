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

"""Add orders plugin metadata table and relationships

Revision ID: 4070806f6972
Revises: 47b69e523451
Create Date: 2014-08-21 14:06:48.237701

"""

# revision identifiers, used by Alembic.
revision = '4070806f6972'
down_revision = '47b69e523451'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()
    table_exists = ctx.dialect.has_table(con.engine, 'order_plugin_metadata')
    if not table_exists:
        op.create_table(
            'order_plugin_metadata',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('order_id', sa.String(length=36), nullable=False),
            sa.Column('key', sa.String(length=255), nullable=False),
            sa.Column('value', sa.String(length=255), nullable=False),
            sa.ForeignKeyConstraint(['order_id'], ['orders.id'],),
            sa.PrimaryKeyConstraint('id'),
        )
