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

"""change_url_length

Revision ID: d2780d5aa510
Revises: dce488646127
Create Date: 2016-03-11 09:39:32.593231

"""

# revision identifiers, used by Alembic.
revision = 'd2780d5aa510'
down_revision = 'dce488646127'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        'container_consumer_metadata',
        'URL',
        type_=sa.String(length=255)
    )
