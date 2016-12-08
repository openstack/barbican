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

"""remove ProjectSecret table

Revision ID: 1bece815014f
Revises: 161f8aceb687
Create Date: 2015-06-23 16:17:50.805295

"""

# revision identifiers, used by Alembic.
revision = '1bece815014f'
down_revision = '161f8aceb687'

from alembic import op


def upgrade():
    op.drop_table('project_secret')
