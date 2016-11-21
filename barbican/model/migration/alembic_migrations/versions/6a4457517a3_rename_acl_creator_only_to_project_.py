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

"""rename ACL creator_only to project_access

Revision ID: 6a4457517a3
Revises: 30dba269cc64
Create Date: 2015-06-03 11:54:55.187875

"""

# revision identifiers, used by Alembic.
revision = '6a4457517a3'
down_revision = '30dba269cc64'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.alter_column('secret_acls', 'creator_only', existing_type=sa.BOOLEAN(),
                    new_column_name='project_access')

    # reverse existing flag value as project_access is negation of creator_only
    op.execute('UPDATE secret_acls SET project_access = NOT project_access',
               execution_options={'autocommit': True})

    op.alter_column('container_acls', 'creator_only',
                    existing_type=sa.BOOLEAN(),
                    new_column_name='project_access')

    # reverse existing flag value as project_access is negation of creator_only
    op.execute('UPDATE container_acls SET project_access = NOT project_access',
               execution_options={'autocommit': True})
