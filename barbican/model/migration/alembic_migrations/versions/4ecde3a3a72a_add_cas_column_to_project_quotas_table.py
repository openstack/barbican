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

"""Add cas column to project quotas table

Revision ID: 4ecde3a3a72a
Revises: 10220ccbe7fa
Create Date: 2015-09-09 09:40:08.540064

"""

# revision identifiers, used by Alembic.
revision = '4ecde3a3a72a'
down_revision = '10220ccbe7fa'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'project_quotas',
        sa.Column('cas', sa.Integer(), nullable=True))
