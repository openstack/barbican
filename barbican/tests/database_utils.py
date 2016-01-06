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
import oslotest.base as oslotest

from barbican.model import models
from barbican.model import repositories


def setup_in_memory_db():
    # Ensure we are using in-memory SQLite database, and creating tables.
    repositories.CONF.set_override("sql_connection", "sqlite:///:memory:",
                                   enforce_type=True)
    repositories.CONF.set_override("db_auto_create", True, enforce_type=True)
    repositories.CONF.set_override("debug", True, enforce_type=True)

    # Ensure the connection is completely closed, so any previous in-memory
    # database can be removed prior to starting the next test run.
    repositories.hard_reset()

    # Start the in-memory database, creating required tables.
    repositories.start()


def in_memory_cleanup():
    repositories.clear()


def get_session():
    return repositories.get_session()


def create_project(external_id="my keystone id", session=None):
    project = models.Project()
    project.external_id = external_id
    project_repo = repositories.get_project_repository()
    project_repo.create_from(project, session=session)
    return project


def create_order(project=None, session=None):
    if not project:
        project = create_project(session=session)

    order = models.Order()
    order.project_id = project.id
    order_repo = repositories.get_order_repository()
    order_repo.create_from(order, session=session)
    return order


class RepositoryTestCase(oslotest.BaseTestCase):
    """Base test case class for in-memory database unit tests.

    Database/Repository oriented unit tests should *not* modify the global
    state in the barbican/model/repositories.py module, as this can lead to
    hard to debug errors. Instead only utilize methods in this fixture.

    Also, database-oriented unit tests extending this class MUST NO INVOKE
    the repositories.start()/clear()/hard_reset() methods!*, otherwise *VERY*
    hard to debug 'Broken Pipe' errors could result!
    """
    def setUp(self):
        super(RepositoryTestCase, self).setUp()
        setup_in_memory_db()

        # Clean up once tests are completed.
        self.addCleanup(in_memory_cleanup)
