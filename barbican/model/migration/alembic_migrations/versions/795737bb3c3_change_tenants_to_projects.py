"""Change tenants to projects

Revision ID: 795737bb3c3
Revises: 254495565185
Create Date: 2014-12-09 15:58:35.535032

"""

# revision identifiers, used by Alembic.
revision = '795737bb3c3'
down_revision = '254495565185'

from alembic import op
import sqlalchemy as sa


def _drop_constraint(ctx, con, table, fk_name_to_try):
    if ctx.dialect.name == 'mysql':
        # MySQL creates different default names for foreign key constraints
        op.drop_constraint(fk_name_to_try,
                           table,
                           type_='foreignkey')


def _change_fk_to_project(ctx, con, table, fk_old, fk_new):
    _drop_constraint(ctx, con, table, fk_old)
    op.alter_column(table, 'tenant_id',
                    type_=sa.String(36),
                    new_column_name='project_id')
    op.create_foreign_key(fk_new, table,
                          'projects', ['project_id'], ['id'])

def upgrade():
    # project_secret table
    ctx = op.get_context()
    con = op.get_bind()

    # ---- Update tenant_secret table to project_secret:

    _drop_constraint(ctx, con, 'tenant_secret', 'tenant_secret_ibfk_1')
    _drop_constraint(ctx, con, 'tenant_secret', 'tenant_secret_ibfk_2')

    op.drop_constraint('_tenant_secret_uc',
                       'tenant_secret',
                       type_='unique')

    op.rename_table('tenant_secret', 'project_secret')
    op.alter_column('project_secret', 'tenant_id',
                    type_=sa.String(36),
                    new_column_name='project_id')

    op.create_unique_constraint('_project_secret_uc', 'project_secret',
                                ['project_id', 'secret_id'])

    # ---- Update tenants table to projects:

    op.rename_table('tenants', 'projects')

    # re-create the foreign key constraints with explicit names.
    op.create_foreign_key('project_secret_project_fk', 'project_secret',
                          'projects', ['project_id'], ['id'])
    op.create_foreign_key('project_secret_secret_fk', 'project_secret',
                          'secrets', ['secret_id'], ['id'])

    # ---- Update containers table:

    _change_fk_to_project(
        ctx, con, 'containers', 'containers_ibfk_1', 'containers_project_fk')

    # ---- Update kek_data table:

    _change_fk_to_project(
        ctx, con, 'kek_data', 'kek_data_ibfk_1', 'kek_data_project_fk')

    # ---- Update orders table:

    _change_fk_to_project(
        ctx, con, 'orders', 'orders_ibfk_1', 'orders_project_fk')
