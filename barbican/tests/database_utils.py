# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Supports database/repositories oriented unit testing.

Warning: Do not merge this content with the utils.py module, as doing so will
break the DevStack functional test discovery process.
"""

from barbican.model import repositories
from barbican.tests import utils


class RepositoryTestCase(utils.BaseTestCase):
    """Base test case class for in-memory database unit tests.

    Database/Repository oriented unit tests should *not* modify the global
    state in the barbican/model/repositories.py module, as this can lead to
    hard to debug errors. Instead only utilize methods in this fixture.
    """
    def setUp(self):
        super(RepositoryTestCase, self).setUp()

        # Ensure we are using in-memory SQLite database, and creating tables.
        repositories.CONF.set_override("sql_connection", "sqlite:///:memory:")
        repositories.CONF.set_override("db_auto_create", True)
        repositories.CONF.set_override("debug", True)

        # Ensure the connection is completely closed, so any previous in-memory
        # database can be removed prior to starting the next test run.
        repositories.hard_reset()

        # Start the in-memory database, creating required tables.
        repositories.start()

        # Clean up once tests are completed.
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        repositories.clear()
