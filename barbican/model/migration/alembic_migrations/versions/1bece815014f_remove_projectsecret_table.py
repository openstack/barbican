"""remove ProjectSecret table

Revision ID: 1bece815014f
Revises: 161f8aceb687
Create Date: 2015-06-23 16:17:50.805295

"""

# revision identifiers, used by Alembic.
revision = '1bece815014f'
down_revision = '161f8aceb687'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


def upgrade():
    op.drop_table('project_secret')


def downgrade():
    op.create_table(
        'project_secret',
        sa.Column('id', sa.VARCHAR(length=36), autoincrement=False,
                  nullable=False),
        sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False,
                  nullable=False),
        sa.Column('updated_at', postgresql.TIMESTAMP(), autoincrement=False,
                  nullable=False),
        sa.Column('deleted_at', postgresql.TIMESTAMP(), autoincrement=False,
                  nullable=True),
        sa.Column('deleted', sa.BOOLEAN(), autoincrement=False,
                  nullable=False),
        sa.Column('status', sa.VARCHAR(length=20), autoincrement=False,
                  nullable=False),
        sa.Column('role', sa.VARCHAR(length=255), autoincrement=False,
                  nullable=True),
        sa.Column('project_id', sa.VARCHAR(length=36), autoincrement=False,
                  nullable=False),
        sa.Column('secret_id', sa.VARCHAR(length=36), autoincrement=False,
                  nullable=False),
        sa.ForeignKeyConstraint(['project_id'], [u'projects.id'],
                                name=u'project_secret_project_fk'),
        sa.ForeignKeyConstraint(['secret_id'], [u'secrets.id'],
                                name=u'project_secret_secret_fk'),
        sa.PrimaryKeyConstraint('id', name=u'project_secret_pkey'),
        sa.UniqueConstraint('project_id', 'secret_id',
                            name=u'_project_secret_uc')
    )
