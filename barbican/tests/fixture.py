#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import fixtures
from oslo_db.sqlalchemy import session
from oslo_utils import timeutils
import sqlalchemy as sa

from barbican.model import models


class SessionQueryFixture(fixtures.Fixture):
    """Fixture for testing queries on a session

    This fixture creates a SQLAlchemy sessionmaker for an in-memory
    sqlite database with sample data.
    """

    def _setUp(self):
        self._engine = session.create_engine('sqlite:///:memory:')
        self.Session = sa.orm.sessionmaker(bind=self._engine)
        self.external_id = 'EXTERNAL_ID'
        models.BASE.metadata.create_all(self._engine)
        self._load_sample_data()

    def _load_sample_data(self):
        sess = self.Session()
        proj = models.Project()
        proj.external_id = self.external_id
        sess.add(proj)
        sess.commit()  # commit to add proj.id

        self._add_secret(sess, proj, 'A',
                         '2016-01-01T00:00:00',
                         '2016-01-01T00:00:00')

        self._add_secret(sess, proj, 'B',
                         '2016-02-01T00:00:00',
                         '2016-02-01T00:00:00')

        self._add_secret(sess, proj, 'C',
                         '2016-03-01T00:00:00',
                         '2016-03-01T00:00:00')

        self._add_secret(sess, proj, 'D',
                         '2016-04-01T00:00:00',
                         '2016-04-01T00:00:00')

        self._add_secret(sess, proj, 'E',
                         '2016-05-01T00:00:00',
                         '2016-05-01T00:00:00')

        self._add_secret(sess, proj, 'F',
                         '2016-06-01T00:00:00',
                         '2016-06-01T00:00:00')

        sess.commit()  # commit all secrets

    def _add_secret(self, session, project, name, created_at, updated_at):
        s = models.Secret()
        s.name = name
        s.created_at = timeutils.parse_isotime(created_at)
        s.updated_at = timeutils.parse_isotime(updated_at)
        s.project_id = project.id
        session.add(s)
