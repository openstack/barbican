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
    op.create_unique_constraint(
            'uc_projects_external_ids', 'projects', ['external_id'])

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
