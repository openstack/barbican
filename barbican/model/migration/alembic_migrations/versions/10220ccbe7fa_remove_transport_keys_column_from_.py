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

"""Remove transport keys column from project quotas table

Revision ID: 10220ccbe7fa
Revises: 3c3b04040bfe
Create Date: 2015-09-09 09:10:23.812681

"""

# revision identifiers, used by Alembic.
revision = '10220ccbe7fa'
down_revision = '3c3b04040bfe'

from alembic import op


def upgrade():
    op.drop_column('project_quotas', 'transport_keys')
