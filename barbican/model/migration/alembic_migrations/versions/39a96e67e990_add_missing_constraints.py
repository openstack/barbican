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

"""Add missing constraints

Revision ID: 39a96e67e990
Revises: 4ecde3a3a72a
Create Date: 2016-01-26 13:18:06.113621

"""

# revision identifiers, used by Alembic.
revision = '39a96e67e990'
down_revision = '4ecde3a3a72a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Add missing projects table keystone_id uniqueness constraint.
    op.create_unique_constraint('uc_projects_external_ids',
                                'projects', ['external_id'])

    # Add missing default for secret_acls' project_access.
    op.alter_column('secret_acls', 'project_access',
                    server_default=sa.sql.expression.true(),
                    existing_type=sa.Boolean,
                    existing_server_default=None,
                    existing_nullable=False)

    # Add missing default for container_acls' project_access.
    op.alter_column('container_acls', 'project_access',
                    server_default=sa.sql.expression.true(),
                    existing_type=sa.Boolean,
                    existing_server_default=None,
                    existing_nullable=False)
