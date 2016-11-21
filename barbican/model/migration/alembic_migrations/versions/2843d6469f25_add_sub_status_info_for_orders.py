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

"""add sub status info for orders

Revision ID: 2843d6469f25
Revises: 2ab3f5371bde
Create Date: 2014-09-16 12:31:15.181380

"""

# revision identifiers, used by Alembic.
revision = '2843d6469f25'
down_revision = '2ab3f5371bde'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('orders',
                  sa.Column('sub_status', sa.String(length=36),
                            nullable=True))
    op.add_column('orders',
                  sa.Column('sub_status_message', sa.String(length=255),
                            nullable=True))
