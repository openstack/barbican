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

"""Update order_retry_tasks table

Revision ID: 30dba269cc64
Revises: 3041b53b95d7
Create Date: 2015-04-01 17:53:25.447919

"""

# revision identifiers, used by Alembic.
revision = '30dba269cc64'
down_revision = '3041b53b95d7'

from oslo_utils import timeutils

from alembic import op
from barbican.model import models as m
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'order_retry_tasks',
        sa.Column(
            'created_at',
            sa.DateTime(),
            nullable=False,
            server_default=str(timeutils.utcnow())))
    op.add_column(
        'order_retry_tasks',
        sa.Column(
            'deleted',
            sa.Boolean(),
            nullable=False,
            server_default='0'))
    op.add_column(
        'order_retry_tasks',
        sa.Column('deleted_at', sa.DateTime(), nullable=True))
    op.add_column(
        'order_retry_tasks',
        sa.Column(
            'status',
            sa.String(length=20),
            nullable=False,
            server_default=m.States.PENDING))
    op.add_column(
        'order_retry_tasks',
        sa.Column(
            'updated_at',
            sa.DateTime(),
            nullable=False,
            server_default=str(timeutils.utcnow())))
