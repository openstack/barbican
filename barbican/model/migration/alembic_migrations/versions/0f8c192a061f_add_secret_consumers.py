# Copyright 2019 OpenStack Foundation
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

"""Add Secret Consumers table

Revision ID: 0f8c192a061f
Revises: 39cf2e645cba
Create Date: 2019-08-19 12:03:08.567230

"""

# revision identifiers, used by Alembic.
revision = "0f8c192a061f"
down_revision = "39cf2e645cba"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        "secret_consumer_metadata",
        # ModelBase
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        # SecretConsumerMetadatum
        sa.Column("secret_id", sa.String(36), nullable=False),
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("service", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(255), nullable=False),
        sa.Column("resource_id", sa.String(36), nullable=False),
        # Constraints and Indexes
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["secret_id"], ["secrets.id"]),
        sa.UniqueConstraint(
            "secret_id", "resource_id", name="_secret_consumer_resource_uc"
        ),
        sa.Index("ix_secret_consumer_metadata_secret_id", "secret_id"),
        sa.Index("ix_secret_consumer_metadata_resource_id", "resource_id"),
    )
