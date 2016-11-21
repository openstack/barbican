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

"""add-cert-to-container-type

Revision ID: cd4106a1a0
Revises: 1e86c18af2dd
Create Date: 2014-06-10 15:07:25.084173

"""

# revision identifiers, used by Alembic.
revision = 'cd4106a1a0'
down_revision = '1e86c18af2dd'

from alembic import op
import sqlalchemy as sa


def upgrade():
    enum_type = sa.Enum(
        'generic', 'rsa', 'dsa', 'certificate',
        name='container_types')
    op.alter_column('containers', 'type', type_=enum_type)
