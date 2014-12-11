"""Change tenants to projects

Revision ID: 795737bb3c3
Revises: 254495565185
Create Date: 2014-12-09 15:58:35.535032

"""

# revision identifiers, used by Alembic.
revision = '795737bb3c3'
down_revision = '254495565185'

from alembic import op


def upgrade():
    # project_secret table
    op.drop_constraint('_tenant_secret_uc', 'tenant_secret')

    op.rename_table('tenant_secret', 'project_secret')
    op.alter_column('project_secret', 'tenant_id',
                    new_column_name='project_id')

    op.create_unique_constraint('_project_secret_uc', 'project_secret',
                                ['project_id', 'secret_id'])

    # projects table
    op.rename_table('tenants', 'projects')

    # containers table
    op.alter_column('containers', 'tenant_id', new_column_name='project_id')

    # kek_data table
    op.alter_column('kek_data', 'tenant_id', new_column_name='project_id')

    # orders table
    op.alter_column('orders', 'tenant_id', new_column_name='project_id')


def downgrade():
    # project_secret table
    op.drop_constraint('_project_secret_uc', 'project_secret')

    op.rename_table('project_secret', 'tenant_secret')
    op.alter_column('tenant_secret', 'project_id',
                    new_column_name='tenant_id')

    op.create_unique_constraint('_project_secret_uc', 'project_secret',
                                ['project_id', 'secret_id'])

    # projects table
    op.rename_table('projects', 'tenants')

    # containers table
    op.alter_column('containers', 'project_id', new_column_name='tenant_id')

    # kek_data table
    op.alter_column('kek_data', 'project_id', new_column_name='tenant_id')

    # orders table
    op.alter_column('orders', 'project_id', new_column_name='tenant_id')
