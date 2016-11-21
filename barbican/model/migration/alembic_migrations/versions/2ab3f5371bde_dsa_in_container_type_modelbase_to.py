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

"""dsa in container type modelbase_to

Revision ID: 2ab3f5371bde
Revises: 4070806f6972
Create Date: 2014-09-02 12:11:43.524247

"""

# revision identifiers, used by Alembic.
revision = '2ab3f5371bde'
down_revision = '4070806f6972'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('container_secret',
                  sa.Column('created_at', sa.DateTime(), nullable=False))
    op.add_column('container_secret',
                  sa.Column('deleted', sa.Boolean(), nullable=False))
    op.add_column('container_secret',
                  sa.Column('deleted_at', sa.DateTime(), nullable=True))
    op.add_column('container_secret',
                  sa.Column('id', sa.String(length=36), nullable=False))
    op.add_column('container_secret',
                  sa.Column('status', sa.String(length=20), nullable=False))
    op.add_column('container_secret',
                  sa.Column('updated_at', sa.DateTime(), nullable=False))

    op.create_primary_key('pk_container_secret', 'container_secret', ['id'])
    op.create_unique_constraint(
        '_container_secret_name_uc',
        'container_secret',
        ['container_id', 'secret_id', 'name']
    )
