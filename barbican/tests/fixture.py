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

import logging as std_logging
import os
import warnings

import fixtures
from oslo_db.sqlalchemy import session
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy import exc as sqla_exc

from barbican.model import models


_TRUE_VALUES = ('True', 'true', '1', 'yes')


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


class NullHandler(std_logging.Handler):
    """custom default NullHandler to attempt to format the record.

    Used in conjunction with
    log_fixture.get_logging_handle_error_fixture to detect formatting errors in
    debug level logs without saving the logs.
    """
    def handle(self, record):
        self.format(record)

    def emit(self, record):
        pass

    def createLock(self):
        self.lock = None


class StandardLogging(fixtures.Fixture):
    """Setup Logging redirection for tests.

    There are a number of things we want to handle with logging in tests:

    * Redirect the logging to somewhere that we can test or dump it later.

    * Ensure that as many DEBUG messages as possible are actually
       executed, to ensure they are actually syntactically valid (they
       often have not been).

    * Ensure that we create useful output for tests that doesn't
      overwhelm the testing system (which means we can't capture the
      100 MB of debug logging on every run).

    To do this we create a logger fixture at the root level, which
    defaults to INFO and create a Null Logger at DEBUG which lets
    us execute log messages at DEBUG but not keep the output.

    To support local debugging OS_DEBUG=True can be set in the
    environment, which will print out the full debug logging.

    There are also a set of overrides for particularly verbose
    modules to be even less than INFO.

    """

    def setUp(self):
        super(StandardLogging, self).setUp()

        # set root logger to debug
        root = std_logging.getLogger()
        root.setLevel(std_logging.INFO)

        # supports collecting debug level for local runs
        if os.environ.get('OS_DEBUG') in _TRUE_VALUES:
            level = std_logging.DEBUG
        else:
            level = std_logging.INFO

        # Collect logs
        fs = '%(asctime)s %(levelname)s [%(name)s] %(message)s'
        self.logger = self.useFixture(
            fixtures.FakeLogger(format=fs, level=None))
        # TODO(sdague): why can't we send level through the fake
        # logger? Tests prove that it breaks, but it's worth getting
        # to the bottom of.
        root.handlers[0].setLevel(level)

        if level > std_logging.DEBUG:
            # Just attempt to format debug level logs, but don't save them
            handler = NullHandler()
            self.useFixture(fixtures.LogHandler(handler, nuke_handlers=False))
            handler.setLevel(std_logging.DEBUG)

        # At times we end up calling back into main() functions in
        # testing. This has the possibility of calling logging.setup
        # again, which completely unwinds the logging capture we've
        # created here. Once we've setup the logging in the way we want,
        # disable the ability for the test to change this.
        def fake_logging_setup(*args):
            pass

        self.useFixture(
            fixtures.MonkeyPatch('oslo_log.log.setup', fake_logging_setup))


class WarningsFixture(fixtures.Fixture):
    """Filters out warnings during test runs."""

    def setUp(self):
        super().setUp()

        self._original_warning_filters = warnings.filters[:]

        warnings.simplefilter('once', DeprecationWarning)

        # Enable deprecation warnings for barbican itself to capture upcoming
        # SQLAlchemy changes

        warnings.filterwarnings(
            'ignore',
            category=sqla_exc.SADeprecationWarning,
        )

        warnings.filterwarnings(
            'error',
            module='barbican',
            category=sqla_exc.SADeprecationWarning,
        )

        # Enable general SQLAlchemy warnings also to ensure we're not doing
        # silly stuff. It's possible that we'll need to filter things out here
        # with future SQLAlchemy versions, but that's a good thing

        warnings.filterwarnings(
            'error',
            module='barbican',
            category=sqla_exc.SAWarning,
        )

        self.addCleanup(self._reset_warning_filters)

    def _reset_warning_filters(self):
        warnings.filters[:] = self._original_warning_filters
