# Copyright 2022 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Update secret consumers unique constraint to mach the updated spec

Revision ID: 8c74e2d7f1ff
Revises: 0f8c192a061f
Create Date: 2022-09-12 13:03:26.428642

"""

# revision identifiers, used by Alembic.
revision = '8c74e2d7f1ff'
down_revision = '0f8c192a061f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    with op.batch_alter_table('secret_consumer_metadata') as batch_op:
        batch_op.alter_column('project_id',
                              existing_type=sa.VARCHAR(length=36),
                              nullable=True)
        batch_op.drop_constraint(
            '_secret_consumer_resource_uc', type_='unique')
        batch_op.create_unique_constraint(
            constraint_name='_secret_consumer_resource_uc',
            columns=['secret_id', 'service', 'resource_type', 'resource_id'])
        batch_op.create_index(
            index_name=op.f('ix_secret_consumer_metadata_project_id'),
            columns=['project_id'],
            unique=False)
        batch_op.create_foreign_key(constraint_name=op.f('fk_project_id'),
                                    referent_table='projects',
                                    local_cols=['project_id'],
                                    remote_cols=['id'])
