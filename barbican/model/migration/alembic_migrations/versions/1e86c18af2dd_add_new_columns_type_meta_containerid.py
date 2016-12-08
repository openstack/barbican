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

"""add new columns type meta containerId

Revision ID: 1e86c18af2dd
Revises: 13d127569afa
Create Date: 2014-06-04 09:53:27.116054

"""

# revision identifiers, used by Alembic.
revision = '1e86c18af2dd'
down_revision = '13d127569afa'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('orders',
                  sa.Column('container_id', sa.String(length=36),
                            nullable=True))
    op.add_column('orders', sa.Column('meta', sa.Text, nullable=True))
    op.add_column('orders',
                  sa.Column('type', sa.String(length=255),
                            nullable=True))
