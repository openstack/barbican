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

"""Add project id to Secrets

Revision ID: 1bc885808c76
Revises: 6a4457517a3
Create Date: 2015-04-24 13:53:29.926426

"""

# revision identifiers, used by Alembic.
revision = '1bc885808c76'
down_revision = '6a4457517a3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('secrets', sa.Column('project_id', sa.String(length=36),
                  nullable=True))
    op.create_index(op.f('ix_secrets_project_id'), 'secrets', ['project_id'],
                    unique=False)
    op.create_foreign_key('secrets_project_fk', 'secrets', 'projects',
                          ['project_id'], ['id'])
