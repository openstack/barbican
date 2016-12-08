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

"""removing redundant fields from order

Revision ID: 254495565185
Revises: 2843d6469f25
Create Date: 2014-09-16 12:09:23.716390

"""

# revision identifiers, used by Alembic.
revision = '254495565185'
down_revision = '2843d6469f25'

from alembic import op


def upgrade():
    op.drop_column('orders', 'secret_mode')
    op.drop_column('orders', 'secret_algorithm')
    op.drop_column('orders', 'secret_bit_length')
    op.drop_column('orders', 'secret_expiration')
    op.drop_column('orders', 'secret_payload_content_type')
    op.drop_column('orders', 'secret_name')
