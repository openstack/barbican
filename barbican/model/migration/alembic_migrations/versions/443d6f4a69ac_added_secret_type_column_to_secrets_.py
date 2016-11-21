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

"""added secret type column to secrets table

Revision ID: 443d6f4a69ac
Revises: aa2cf96a1d5
Create Date: 2015-02-16 12:35:12.876413

"""

# revision identifiers, used by Alembic.
revision = '443d6f4a69ac'
down_revision = 'aa2cf96a1d5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('secrets', sa.Column('secret_type', sa.String(length=255),
                  nullable=False, server_default="opaque"))
