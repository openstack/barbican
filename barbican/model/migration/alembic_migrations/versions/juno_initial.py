# Copyright 2015 OpenStack Foundation
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

"""juno_initial

Revision ID: juno
Revises: None

"""

# revision identifiers, used by Alembic.
revision = 'juno'
down_revision = '1a0c2cdafb38'


from barbican.model.migration.alembic_migrations import container_init_ops
from barbican.model.migration.alembic_migrations import encrypted_init_ops
from barbican.model.migration.alembic_migrations import kek_init_ops
from barbican.model.migration.alembic_migrations import order_ops
from barbican.model.migration.alembic_migrations import projects_init_ops
from barbican.model.migration.alembic_migrations import secrets_init_ops
from barbican.model.migration.alembic_migrations import transport_keys_init_ops


def upgrade():
    projects_init_ops.upgrade()
    secrets_init_ops.upgrade()
    container_init_ops.upgrade()
    kek_init_ops.upgrade()
    encrypted_init_ops.upgrade()
    order_ops.upgrade()
    transport_keys_init_ops.upgrade()
