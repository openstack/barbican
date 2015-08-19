"""fill project_id to secrets where missing

Revision ID: 161f8aceb687
Revises: 1bc885808c76
Create Date: 2015-06-22 15:58:03.131256

"""

# revision identifiers, used by Alembic.
revision = '161f8aceb687'
down_revision = '1bc885808c76'

from alembic import op
import sqlalchemy as sa


def _get_database_metadata():
    con = op.get_bind()
    metadata = sa.MetaData(bind=con)
    metadata.reflect()
    return metadata


def upgrade():
    metadata = _get_database_metadata()

    # Get relevant tables
    secrets = metadata.tables['secrets']
    project_secret = metadata.tables['project_secret']

    # Add project_id to the secrets
    op.execute(secrets.update().
               values({'project_id': project_secret.c.project_id}).
               where(secrets.c.id == project_secret.c.secret_id).
               where(secrets.c.project_id == None)
               )

    # make project_id no longer nullable
    op.alter_column('secrets', 'project_id', nullable=False)
