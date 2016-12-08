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

"""Remove size limits on meta table values

Revision ID: 3041b53b95d7
Revises: 1a7cf79559e3
Create Date: 2015-04-08 15:43:32.852529

"""

# revision identifiers, used by Alembic.
revision = '3041b53b95d7'
down_revision = '1a7cf79559e3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        'order_barbican_metadata',
        'value',
        type_=sa.Text()
    )

    op.alter_column(
        'certificate_authority_metadata',
        'value',
        type_=sa.Text()
    )
