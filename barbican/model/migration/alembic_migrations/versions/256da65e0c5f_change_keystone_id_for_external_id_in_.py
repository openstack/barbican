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

"""Change keystone_id for external_id in Project model

Revision ID: 256da65e0c5f
Revises: 795737bb3c3
Create Date: 2014-12-22 03:55:29.072375

"""

# revision identifiers, used by Alembic.
revision = '256da65e0c5f'
down_revision = '795737bb3c3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('projects', 'keystone_id',
                    type_=sa.String(36),
                    new_column_name='external_id')
