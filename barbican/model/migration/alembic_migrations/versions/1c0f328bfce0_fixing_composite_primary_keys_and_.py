"""Fixing composite primary keys and adding indexes to foreign key

Revision ID: 1c0f328bfce0
Revises: 3d36a26b88af
Create Date: 2015-03-04 17:09:41.479708

"""

# revision identifiers, used by Alembic.
revision = '1c0f328bfce0'
down_revision = '2d21598e7e70'

from alembic import op
import sqlalchemy as sa


def _drop_constraint(ctx, name, table):
    if ctx.dialect.name == 'mysql':
        # MySQL won't allow some operations with constraints in place
        op.drop_constraint(name, table, type_='foreignkey')


def upgrade():
    op.create_index(op.f('ix_certificate_authority_metadata_ca_id'), 'certificate_authority_metadata', ['ca_id'], unique=False)
    op.create_index(op.f('ix_certificate_authority_metadata_key'), 'certificate_authority_metadata', ['key'], unique=False)
    op.create_index(op.f('ix_container_consumer_metadata_container_id'), 'container_consumer_metadata', ['container_id'], unique=False)
    op.create_index(op.f('ix_container_secret_container_id'), 'container_secret', ['container_id'], unique=False)
    op.create_index(op.f('ix_container_secret_secret_id'), 'container_secret', ['secret_id'], unique=False)
    op.create_index(op.f('ix_containers_project_id'), 'containers', ['project_id'], unique=False)
    op.create_index(op.f('ix_encrypted_data_kek_id'), 'encrypted_data', ['kek_id'], unique=False)
    op.create_index(op.f('ix_encrypted_data_secret_id'), 'encrypted_data', ['secret_id'], unique=False)
    op.create_index(op.f('ix_kek_data_project_id'), 'kek_data', ['project_id'], unique=False)
    op.create_index(op.f('ix_order_barbican_metadata_order_id'), 'order_barbican_metadata', ['order_id'], unique=False)
    op.create_index(op.f('ix_order_plugin_metadata_order_id'), 'order_plugin_metadata', ['order_id'], unique=False)
    op.create_index(op.f('ix_order_retry_tasks_order_id'), 'order_retry_tasks', ['order_id'], unique=False)
    op.create_index(op.f('ix_orders_container_id'), 'orders', ['container_id'], unique=False)
    op.create_index(op.f('ix_orders_project_id'), 'orders', ['project_id'], unique=False)
    op.create_index(op.f('ix_orders_secret_id'), 'orders', ['secret_id'], unique=False)

    ctx = op.get_context()
    _drop_constraint(ctx, 'preferred_certificate_authorities_ibfk_1', 'preferred_certificate_authorities')

    op.alter_column('preferred_certificate_authorities', 'ca_id',
               existing_type=sa.VARCHAR(length=36),
               nullable=False)

    op.create_foreign_key('preferred_certificate_authorities_fk', 'preferred_certificate_authorities',
                          'certificate_authorities', ['ca_id'], ['id'])

    op.create_index(op.f('ix_preferred_certificate_authorities_ca_id'), 'preferred_certificate_authorities', ['ca_id'], unique=False)
    op.create_index(op.f('ix_preferred_certificate_authorities_project_id'), 'preferred_certificate_authorities', ['project_id'], unique=True)
    op.create_index(op.f('ix_project_certificate_authorities_ca_id'), 'project_certificate_authorities', ['ca_id'], unique=False)
    op.create_index(op.f('ix_project_certificate_authorities_project_id'), 'project_certificate_authorities', ['project_id'], unique=False)
    op.create_index(op.f('ix_project_secret_project_id'), 'project_secret', ['project_id'], unique=False)
    op.create_index(op.f('ix_project_secret_secret_id'), 'project_secret', ['secret_id'], unique=False)
    op.create_index(op.f('ix_secret_store_metadata_secret_id'), 'secret_store_metadata', ['secret_id'], unique=False)


def downgrade():
    ctx = op.get_context()
    _drop_constraint(ctx, 'secret_store_metadata_ibfk_1', 'secret_store_metadata')
    op.drop_index(op.f('ix_secret_store_metadata_secret_id'), table_name='secret_store_metadata')

    op.drop_constraint('project_secret_secret_fk', 'project_secret', type_='foreignkey')
    op.drop_index(op.f('ix_project_secret_secret_id'), table_name='project_secret')
    op.drop_index(op.f('ix_project_secret_project_id'), table_name='project_secret')
    op.drop_index(op.f('ix_project_certificate_authorities_project_id'), table_name='project_certificate_authorities')

    _drop_constraint(ctx, 'project_certificate_authorities_ibfk_1', 'project_certificate_authorities')
    op.drop_index(op.f('ix_project_certificate_authorities_ca_id'), table_name='project_certificate_authorities')

    op.drop_constraint('preferred_certificate_authorities_fk', 'preferred_certificate_authorities', type_='foreignkey')
    op.drop_index(op.f('ix_preferred_certificate_authorities_project_id'), table_name='preferred_certificate_authorities')

    op.drop_index(op.f('ix_preferred_certificate_authorities_ca_id'), table_name='preferred_certificate_authorities')
    op.alter_column('preferred_certificate_authorities', 'ca_id',
               existing_type=sa.VARCHAR(length=36),
               nullable=True)

    if ctx.dialect.name == 'mysql':
        # add the fk back in for the MySQL impl
        op.create_foreign_key('preferred_certificate_authorities_ibfk_1', 'preferred_certificate_authorities',
                              'certificate_authorities', ['ca_id'], ['id'])

    _drop_constraint(ctx, 'orders_ibfk_2', 'orders')
    op.drop_index(op.f('ix_orders_secret_id'), table_name='orders')

    op.drop_constraint('orders_project_fk', 'orders', type_='foreignkey')
    op.drop_index(op.f('ix_orders_project_id'), table_name='orders')

    _drop_constraint(ctx, 'orders_ibfk_3', 'orders')
    op.drop_index(op.f('ix_orders_container_id'), table_name='orders')

    _drop_constraint(ctx, 'order_retry_tasks_ibfk_1', 'order_retry_tasks')
    op.drop_index(op.f('ix_order_retry_tasks_order_id'), table_name='order_retry_tasks')

    _drop_constraint(ctx, 'order_plugin_metadata_ibfk_1', 'order_plugin_metadata')
    op.drop_index(op.f('ix_order_plugin_metadata_order_id'), table_name='order_plugin_metadata')

    _drop_constraint(ctx, 'order_barbican_metadata_ibfk_1', 'order_barbican_metadata')
    op.drop_index(op.f('ix_order_barbican_metadata_order_id'), table_name='order_barbican_metadata')

    op.drop_constraint('kek_data_project_fk', 'kek_data', type_='foreignkey')
    op.drop_index(op.f('ix_kek_data_project_id'), table_name='kek_data')

    _drop_constraint(ctx, 'encrypted_data_ibfk_1', 'encrypted_data')
    op.drop_index(op.f('ix_encrypted_data_secret_id'), table_name='encrypted_data')

    _drop_constraint(ctx, 'encrypted_data_ibfk_2', 'encrypted_data')
    op.drop_index(op.f('ix_encrypted_data_kek_id'), table_name='encrypted_data')

    op.drop_constraint('containers_project_fk', 'containers', type_='foreignkey')
    op.drop_index(op.f('ix_containers_project_id'), table_name='containers')

    _drop_constraint(ctx, 'container_secret_ibfk_2', 'container_secret')
    op.drop_index(op.f('ix_container_secret_secret_id'), table_name='container_secret')

    _drop_constraint(ctx, 'container_secret_ibfk_1', 'container_secret')
    op.drop_index(op.f('ix_container_secret_container_id'), table_name='container_secret')

    _drop_constraint(ctx, 'container_consumer_metadata_ibfk_1', 'container_consumer_metadata')
    op.drop_index(op.f('ix_container_consumer_metadata_container_id'), table_name='container_consumer_metadata')

    op.drop_index(op.f('ix_certificate_authority_metadata_key'), table_name='certificate_authority_metadata')

    _drop_constraint(ctx, 'certificate_authority_metadata_ibfk_1', 'certificate_authority_metadata')
    op.drop_index(op.f('ix_certificate_authority_metadata_ca_id'), table_name='certificate_authority_metadata')
