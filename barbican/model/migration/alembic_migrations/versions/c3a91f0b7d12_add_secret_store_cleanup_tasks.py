# Copyright 2026 Red Hat, Inc.
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

"""Add secret_store_cleanup_tasks for async plugin object delete

Revision ID: c3a91f0b7d12
Revises: 8c74e2d7f1ff
Create Date: 2026-10-01 16:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'c3a91f0b7d12'
down_revision = '8c74e2d7f1ff'

from alembic import op
import sqlalchemy as sa

import barbican.model.models


def upgrade():
    op.create_table(
        'secret_store_cleanup_tasks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('secret_id', sa.String(length=36), nullable=True),
        sa.Column('plugin_name', sa.String(length=255), nullable=False),
        sa.Column('plugin_meta', barbican.model.models.JsonBlob(),
                  nullable=False),
        sa.Column('reason', sa.String(length=64), nullable=False),
        sa.Column('retry_at', sa.DateTime(), nullable=False),
        sa.Column('retry_count', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB',
    )
    op.create_index(
        op.f('ix_secret_store_cleanup_tasks_secret_id'),
        'secret_store_cleanup_tasks',
        ['secret_id'],
        unique=False)
    op.create_index(
        op.f('ix_secret_store_cleanup_tasks_retry_at'),
        'secret_store_cleanup_tasks',
        ['retry_at'],
        unique=False)
