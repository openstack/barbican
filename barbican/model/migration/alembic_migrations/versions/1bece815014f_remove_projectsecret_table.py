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
