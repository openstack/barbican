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

import datetime
import time
from unittest import mock

import eventlet

from barbican.model import models
from barbican.model import repositories
from barbican.queue import retry_scheduler
from barbican.tests import database_utils
from barbican.tests import utils


# Oslo messaging RPC server uses eventlet.
eventlet.monkey_patch()


INITIAL_DELAY_SECONDS = 5.0
NEXT_RETRY_SECONDS = 5.0


def is_interval_in_expected_range(interval):
    return NEXT_RETRY_SECONDS * .8 <= interval < NEXT_RETRY_SECONDS * 1.2


class WhenRunningPeriodicServerRetryLogic(database_utils.RepositoryTestCase):
    """Tests the retry logic invoked by the periodic task retry server.

    These tests are only concerned with the logic of the invoked periodic
    task method. Testing of whether or not the periodic tasks are
    actually invoked per configured schedule configuration is deferred to the
    tests in :class:`WhenRunningPeriodicServer`.
    """

    def setUp(self):
        super(WhenRunningPeriodicServerRetryLogic, self).setUp()

        retry_scheduler.CONF.set_override(
            "initial_delay_seconds",
            2 * INITIAL_DELAY_SECONDS,
            group='retry_scheduler')

        retry_scheduler.CONF.set_override(
            "periodic_interval_max_seconds",
            NEXT_RETRY_SECONDS,
            group='retry_scheduler')

        self.queue_client = mock.MagicMock()

        self.periodic_server = retry_scheduler.PeriodicServer(
            queue_resource=self.queue_client)

    def tearDown(self):
        super(WhenRunningPeriodicServerRetryLogic, self).tearDown()
        self.periodic_server.stop()

    def test_should_perform_retry_processing_no_tasks(self):
        interval = self.periodic_server._check_retry_tasks()

        self.assertTrue(is_interval_in_expected_range(interval))

    def test_should_perform_retry_processing_one_task(self):
        # Add one retry task.
        args, kwargs, retry_repo = self._create_retry_task()

        # Retrieve this entity.
        entities, _, _, total = retry_repo.get_by_create_date()
        self.assertEqual(1, total)

        time.sleep(1)

        interval = self.periodic_server._check_retry_tasks()

        # Attempt to retrieve this entity, should have been deleted above.
        entities, _, _, total = retry_repo.get_by_create_date(
            suppress_exception=True)
        self.assertEqual(0, total)

        self.assertTrue(is_interval_in_expected_range(interval))
        self.queue_client.test_task.assert_called_once_with(
            *args, **kwargs
        )

    @mock.patch('barbican.model.repositories.commit')
    def test_should_fail_and_force_a_rollback(self, mock_commit):
        mock_commit.side_effect = Exception()

        # Add one retry task.
        args, kwargs, retry_repo = self._create_retry_task()

        # Retrieve this entity.
        entities, _, _, total = retry_repo.get_by_create_date()
        self.assertEqual(1, total)

        time.sleep(1)

        self.periodic_server._check_retry_tasks()

        # Attempt to retrieve this entity, should not have been deleted above.
        entities, _, _, total = retry_repo.get_by_create_date(
            suppress_exception=True)
        self.assertEqual(1, total)

    @mock.patch('barbican.model.repositories.get_order_retry_tasks_repository')
    def test_should_fail_process_retry(self, mock_get_repo):
        mock_get_repo.return_value.get_by_create_date.side_effect = \
            Exception()

        periodic_server_with_mock_repo = retry_scheduler.PeriodicServer(
            queue_resource=self.queue_client)

        interval = periodic_server_with_mock_repo._check_retry_tasks()

        self.assertTrue(is_interval_in_expected_range(interval))

    def _create_retry_task(self):
        # Add one retry task:
        task = 'test_task'
        args = ('foo', 'bar')
        kwargs = {'k_foo': 1, 'k_bar': 2}

        order = database_utils.create_order()

        retry = models.OrderRetryTask()
        retry.order_id = order.id
        retry.retry_at = datetime.datetime.utcnow()
        retry.retry_task = task
        retry.retry_args = args
        retry.retry_kwargs = kwargs

        retry_repo = repositories.get_order_retry_tasks_repository()
        retry_repo.create_from(retry)

        database_utils.get_session().commit()

        return args, kwargs, retry_repo


class WhenRunningPeriodicServer(utils.BaseTestCase):
    """Tests the timing-related functionality of the periodic task retry server.

    These tests are only concerned with whether or not periodic tasks are
    actually invoked per configured schedule configuration. The logic of the
    invoked periodic task method itself is deferred to the tests in
    :class:`WhenRunningPeriodicServerRetryLogic`.
    """

    def setUp(self):
        super(WhenRunningPeriodicServer, self).setUp()

        retry_scheduler.CONF.set_override(
            "initial_delay_seconds",
            INITIAL_DELAY_SECONDS,
            group='retry_scheduler')

        self.database_patcher = _DatabasePatcherHelper()
        self.database_patcher.start()

        self.periodic_server = _PeriodicServerStub(queue_resource=None)
        self.periodic_server.start()

    def tearDown(self):
        super(WhenRunningPeriodicServer, self).tearDown()
        self.periodic_server.stop()
        self.database_patcher.stop()

    def test_should_have_invoked_periodic_task_after_initial_delay(self):
        # Wait a bit longer than the initial delay.
        time.sleep(3 * INITIAL_DELAY_SECONDS / 2)

        self.assertEqual(1, self.periodic_server.invoke_count)

    def test_should_have_invoked_periodic_task_twice(self):
        # Wait a bit longer than the initial delay plus retry interval.
        time.sleep(INITIAL_DELAY_SECONDS + 2 * NEXT_RETRY_SECONDS)

        self.assertEqual(2, self.periodic_server.invoke_count)

    def test_should_have_not_invoked_periodic_task_yet(self):
        # Wait a short time, before the initial delay expires.
        time.sleep(1)

        self.assertEqual(0, self.periodic_server.invoke_count)


class _PeriodicServerStub(retry_scheduler.PeriodicServer):
    """Periodic server testing stub class.

    This class overrides the periodic retry task so that we can track how
    many times it has been invoked by the Oslo periodic task process.
    """
    def __init__(self, queue_resource=None):
        super(_PeriodicServerStub, self).__init__()

        self.invoke_count = 0

    def _check_retry_tasks(self):
        """Override the periodic method, indicating we have called it."""
        self.invoke_count += 1

        return NEXT_RETRY_SECONDS


class _DatabasePatcherHelper(object):
    """This test suite does not test database interactions, so just stub it."""
    def __init__(self):
        super(_DatabasePatcherHelper, self).__init__()

        database_config = {
            'return_value': None
        }
        self.database_patcher = mock.patch(
            'barbican.model.repositories.setup_database_engine_and_factory',
            **database_config
        )

    def start(self):
        self.database_patcher.start()

    def stop(self):
        self.database_patcher.stop()
