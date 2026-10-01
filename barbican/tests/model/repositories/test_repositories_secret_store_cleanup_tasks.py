# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

from oslo_utils import timeutils

from barbican.common import config
from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingSecretStoreCleanupTaskRepository(
        database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingSecretStoreCleanupTaskRepository, self).setUp()
        self.repo = repositories.SecretStoreCleanupTaskRepo()
        self.now = timeutils.utcnow()

    def test_get_cleanup_task(self):
        session = self.repo.get_session()
        task = self._create_task(session)

        fetched = self.repo.get(task.id, session=session)

        self.assertEqual(task.id, fetched.id)
        self.assertEqual('plugin.Name', fetched.plugin_name)
        self.assertEqual({'secret_id': 'obj-1'}, fetched.plugin_meta)
        self.assertEqual(
            models.SecretStoreCleanupReason.SOURCE_AFTER_SUCCESS,
            fetched.reason)

    def test_get_for_update_returns_row(self):
        session = self.repo.get_session()
        task = self._create_task(session)

        fetched = self.repo.get_for_update(task.id, session=session)

        self.assertEqual(task.id, fetched.id)

    def test_get_for_update_skips_deleted(self):
        session = self.repo.get_session()
        task = self._create_task(session)
        task.delete(session=session)
        session.commit()

        fetched = self.repo.get_for_update(
            task.id, session=session, suppress_exception=True)

        self.assertIsNone(fetched)

    def test_get_due_filters_by_retry_time(self):
        session = self.repo.get_session()
        future = self.now + datetime.timedelta(hours=1)
        past = self.now - datetime.timedelta(hours=1)
        due = self._create_task(session, retry_at=past)
        self._create_task(session, retry_at=future)

        entities, offset, limit, total = self.repo.get_due(
            only_at_or_before_this_date=self.now,
            session=session,
            suppress_exception=True)

        self.assertEqual(1, total)
        self.assertEqual(due.id, entities[0].id)
        self.assertEqual(0, offset)
        self.assertEqual(config.CONF.default_limit_paging, limit)

    def test_get_due_skips_error_and_deleted(self):
        session = self.repo.get_session()
        past = self.now - datetime.timedelta(hours=1)
        self._create_task(session, retry_at=past,
                          status=models.States.ERROR)
        deleted = self._create_task(session, retry_at=past)
        deleted.delete(session=session)
        session.commit()

        entities, _, _, total = self.repo.get_due(
            only_at_or_before_this_date=self.now,
            session=session,
            suppress_exception=True)

        self.assertEqual(0, total)
        self.assertEqual([], entities)

    def test_should_raise_no_result_found_no_exception(self):
        session = self.repo.get_session()

        entities, offset, limit, total = self.repo.get_due(
            session=session,
            suppress_exception=True)

        self.assertEqual([], entities)
        self.assertEqual(0, offset)
        self.assertEqual(config.CONF.default_limit_paging, limit)
        self.assertEqual(0, total)

    def test_should_raise_no_result_found_with_exceptions(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_due,
            session=session,
            suppress_exception=False)

    def _create_task(self, session, retry_at=None, status=None):
        task = database_utils.create_secret_store_cleanup_task(
            secret_id='secret-id',
            plugin_meta={'secret_id': 'obj-1'},
            retry_at=retry_at or self.now,
            status=status,
            session=session)
        session.commit()
        return task
