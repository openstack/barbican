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

    ctx = op.get_context()
    con = op.get_bind()

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
