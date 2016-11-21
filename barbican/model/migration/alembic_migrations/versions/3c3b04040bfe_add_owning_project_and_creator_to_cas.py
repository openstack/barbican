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

"""add owning project and creator to CAs

Revision ID: 3c3b04040bfe
Revises: 156cd9933643
Create Date: 2015-09-04 12:22:22.745824

"""

# revision identifiers, used by Alembic.
revision = '3c3b04040bfe'
down_revision = '156cd9933643'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('certificate_authorities',
                  sa.Column('creator_id', sa.String(length=255),
                            nullable=True))
    op.add_column('certificate_authorities',
                  sa.Column('project_id', sa.String(length=36),
                            nullable=True))
    op.create_foreign_key('cas_project_fk', 'certificate_authorities',
                          'projects', ['project_id'], ['id'])
