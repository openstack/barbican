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

"""Add OrderRetryTask

Revision ID: aa2cf96a1d5
Revises: 256da65e0c5f
Create Date: 2015-01-19 10:27:19.179196

"""

# revision identifiers, used by Alembic.
revision = "aa2cf96a1d5"
down_revision = "256da65e0c5f"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        "order_retry_tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("order_id", sa.String(length=36), nullable=False),
        sa.Column("retry_task", sa.Text(), nullable=False),
        sa.Column("retry_at", sa.DateTime(), nullable=False),
        sa.Column("retry_args", sa.Text(), nullable=False),
        sa.Column("retry_kwargs", sa.Text(), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["order_id"], ["orders.id"]),
        sa.PrimaryKeyConstraint("id"),
        mysql_engine="InnoDB"
    )
