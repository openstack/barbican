# Copyright (c) 2013-2014 Rackspace, Inc.
#
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

import mock

from barbican.model import repositories
from barbican import queue
from barbican.queue import server
from barbican.tasks import common
from barbican.tests import database_utils
from barbican.tests import utils


class WhenUsingTransactionalDecorator(utils.BaseTestCase):
    """Test using the 'transactional' decorator in server.py.

    Note that only the 'I am a server' logic is tested here, as the alternate
    mode is only used for direct invocation of Task methods in the standalone
    server mode, which is also thoroughly tested in WhenUsingBeginTypeOrderTask
    below.
    """

    def setUp(self):
        super(WhenUsingTransactionalDecorator, self).setUp()

        # Ensure we always thing we are in 'I am a server' mode.
        is_server_side_config = {
            'return_value': True
        }
        self.is_server_side_patcher = mock.patch(
            'barbican.queue.is_server_side',
            **is_server_side_config
        )
        self.is_server_side_patcher.start()

        self.commit_patcher = mock.patch(
            'barbican.model.repositories.commit'
        )
        self.commit_mock = self.commit_patcher.start()

        self.rollback_patcher = mock.patch(
            'barbican.model.repositories.rollback'
        )
        self.rollback_mock = self.rollback_patcher.start()

        self.clear_patcher = mock.patch(
            'barbican.model.repositories.clear'
        )
        self.clear_mock = self.clear_patcher.start()

        self.args = ('foo', 'bar')
        self.kwargs = {'k_foo': 1, 'k_bar': 2}

        # Class/decorator under test.
        class TestClass(object):
            my_args = None
            my_kwargs = None
            is_exception_needed = False

            @server.transactional
            def test_method(self, *args, **kwargs):
                if self.is_exception_needed:
                    raise ValueError()
                self.my_args = args
                self.my_kwargs = kwargs
        self.test_object = TestClass()

    def tearDown(self):
        super(WhenUsingTransactionalDecorator, self).tearDown()
        self.is_server_side_patcher.stop()
        self.commit_patcher.stop()
        self.rollback_patcher.stop()
        self.clear_patcher.stop()

    def test_should_commit(self):
        self.test_object.test_method(*self.args, **self.kwargs)

        self.assertEqual(self.args, self.test_object.my_args)
        self.assertEqual(self.kwargs, self.test_object.my_kwargs)

        self.assertEqual(self.commit_mock.call_count, 1)
        self.assertEqual(self.rollback_mock.call_count, 0)
        self.assertEqual(self.clear_mock.call_count, 1)

    def test_should_rollback(self):
        self.test_object.is_exception_needed = True

        self.test_object.test_method(*self.args, **self.kwargs)

        self.assertEqual(self.commit_mock.call_count, 0)
        self.assertEqual(self.rollback_mock.call_count, 1)
        self.assertEqual(self.clear_mock.call_count, 1)


class WhenUsingRetryableOrderDecorator(utils.BaseTestCase):
    """Test using the 'retryable_order' decorator in server.py."""

    def setUp(self):
        super(WhenUsingRetryableOrderDecorator, self).setUp()

        self.schedule_retry_tasks_patcher = mock.patch(
            'barbican.queue.server.schedule_order_retry_tasks'
        )
        self.schedule_retry_tasks_mock = (
            self.schedule_retry_tasks_patcher.start()
        )

        self.order_id = 'order-id'
        self.args = ('foo', 'bar')
        self.kwargs = {'k_foo': 1, 'k_bar': 2}

        # Class/decorator under test.
        class TestClass(object):
            self.order_id = None
            my_args = None
            my_kwargs = None
            is_exception_needed = False
            result = common.FollowOnProcessingStatusDTO()

            @server.retryable_order
            def test_method(self, order_id, *args, **kwargs):
                if self.is_exception_needed:
                    raise ValueError()
                self.order_id = order_id
                self.my_args = args
                self.my_kwargs = kwargs
                return self.result
        self.test_object = TestClass()
        self.test_method = TestClass.test_method

    def tearDown(self):
        super(WhenUsingRetryableOrderDecorator, self).tearDown()
        self.schedule_retry_tasks_patcher.stop()

    def test_should_successfully_schedule_a_task_for_retry(self):
        self.test_object.test_method(self.order_id, *self.args, **self.kwargs)

        self.assertEqual(self.order_id, self.test_object.order_id)
        self.assertEqual(self.args, self.test_object.my_args)
        self.assertEqual(self.kwargs, self.test_object.my_kwargs)

        self.assertEqual(self.schedule_retry_tasks_mock.call_count, 1)
        self.schedule_retry_tasks_mock.assert_called_with(
            mock.ANY,
            self.test_object.result,
            self.order_id,
            *self.args,
            **self.kwargs)

    def test_retry_should_not_be_scheduled_if_exception_is_raised(self):
        self.test_object.is_exception_needed = True

        self.assertRaises(
            ValueError,
            self.test_object.test_method,
            self.order_id,
            self.args,
            self.kwargs,
        )

        self.assertEqual(self.schedule_retry_tasks_mock.call_count, 0)


class WhenCallingScheduleOrderRetryTasks(database_utils.RepositoryTestCase):
    """Test calling schedule_order_retry_tasks() in server.py."""

    def setUp(self):
        super(WhenCallingScheduleOrderRetryTasks, self).setUp()

        self.project = database_utils.create_project()
        self.order = database_utils.create_order(self.project)
        database_utils.get_session().commit()

        self.repo = repositories.OrderRetryTaskRepo()

        self.result = common.FollowOnProcessingStatusDTO()

        self.args = ['args-foo', 'args-bar']
        self.kwargs = {'order_id': self.order.id, 'foo': 1, 'bar': 2}
        self.date_to_retry_at = (
            datetime.datetime.utcnow() + datetime.timedelta(
                milliseconds=self.result.retry_msec)
        )

    def test_should_not_schedule_task_due_to_no_result(self):
        retry_rpc_method = server.schedule_order_retry_tasks(None, None, None)

        self.assertIsNone(retry_rpc_method)

    def test_should_not_schedule_task_due_to_no_action_required_result(self):
        self.result.retry_task = common.RetryTasks.NO_ACTION_REQUIRED

        retry_rpc_method = server.schedule_order_retry_tasks(
            None, self.result, None)

        self.assertIsNone(retry_rpc_method)

    def test_should_schedule_invoking_task_for_retry(self):
        self.result.retry_task = common.RetryTasks.INVOKE_SAME_TASK

        # Schedule this test method as the passed-in 'retry' function.
        retry_rpc_method = server.schedule_order_retry_tasks(
            self.test_should_schedule_invoking_task_for_retry,
            self.result,
            None,  # Not used.
            *self.args,
            **self.kwargs)
        database_utils.get_session().commit()  # Flush to the database.

        self.assertEqual(
            'test_should_schedule_invoking_task_for_retry', retry_rpc_method)
        self._verify_retry_task_entity(
            'test_should_schedule_invoking_task_for_retry')

    def test_should_schedule_certificate_status_task_for_retry(self):
        self.result.retry_task = (
            common.RetryTasks.INVOKE_CERT_STATUS_CHECK_TASK
        )

        # Schedule this test method as the passed-in 'retry' function.
        retry_rpc_method = server.schedule_order_retry_tasks(
            None,  # Should be ignored for non-self retries.
            self.result,
            None,  # Not used.
            *self.args,
            **self.kwargs)
        database_utils.get_session().commit()  # Flush to the database.

        self.assertEqual(
            'check_certificate_status', retry_rpc_method)
        self._verify_retry_task_entity(
            'check_certificate_status')

    def _verify_retry_task_entity(self, retry_task):
        # Retrieve the task retry entity created above and verify it.
        entities, offset, limit, total = self.repo.get_by_create_date()
        self.assertEqual(1, total)
        retry_model = entities[0]
        self.assertEqual(retry_task, retry_model.retry_task)
        self.assertEqual(self.args, retry_model.retry_args)
        self.assertEqual(self.kwargs, retry_model.retry_kwargs)
        self.assertEqual(0, retry_model.retry_count)

        # Compare retry_at times.
        # Note that the expected retry_at time is computed at setUp() time, but
        # the retry_at time on the task retry entity/model is computed and set
        # a few milliseconds after this setUp() time, hence they will vary by a
        # small amount of time.
        delta = retry_model.retry_at - self.date_to_retry_at
        delta_seconds = delta.seconds
        self.assertEqual(True, delta_seconds <= 2)


class WhenCallingTasksMethod(utils.BaseTestCase):
    """Test calling methods on the Tasks class."""

    def setUp(self):
        super(WhenCallingTasksMethod, self).setUp()

        # Mock the 'am I a server process?' flag used by the decorator around
        #   all task methods. Since this test class focuses on testing task
        #   method behaviors, this flag is set to false to allow for direct
        #   testing of these tasks without database transactional interference.
        is_server_side_config = {
            'return_value': False
        }
        self.is_server_side_patcher = mock.patch(
            'barbican.queue.is_server_side',
            **is_server_side_config
        )
        self.is_server_side_patcher.start()

        self.tasks = server.Tasks()

    def tearDown(self):
        super(WhenCallingTasksMethod, self).tearDown()
        self.is_server_side_patcher.stop()

    @mock.patch('barbican.tasks.resources.BeginTypeOrder')
    def test_should_process_order(self, mock_begin_order):
        mock_begin_order.return_value.process.return_value = None

        self.tasks.process_type_order(
            None, self.order_id, self.external_project_id)

        mock_begin_order.return_value.process.assert_called_with(
            self.order_id, self.external_project_id)

    @mock.patch('barbican.tasks.resources.UpdateOrder')
    def test_should_update_order(self, mock_update_order):
        mock_update_order.return_value.process.return_value = None
        updated_meta = {}

        self.tasks.update_order(
            None, self.order_id, self.external_project_id, updated_meta)
        mock_update_order.return_value.process.assert_called_with(
            self.order_id, self.external_project_id, updated_meta
        )

    @mock.patch('barbican.tasks.resources.CheckCertificateStatusOrder')
    def test_should_check_certificate_order(self, mock_check_cert_order):
        mock_check_cert_order.return_value.process.return_value = None

        self.tasks.check_certificate_status(
            None, self.order_id, self.external_project_id)
        mock_check_cert_order.return_value.process.assert_called_with(
            self.order_id, self.external_project_id
        )

    @mock.patch('barbican.tasks.resources.BeginTypeOrder')
    def test_process_order_catch_exception(self, mock_begin_order):
        """Test that BeginTypeOrder's process() handles all exceptions."""
        mock_begin_order.return_value._process.side_effect = Exception()

        self.tasks.process_type_order(None, self.order_id,
                                      self.external_project_id)


class WhenUsingTaskServer(utils.BaseTestCase):
    """Test using the asynchronous task client."""

    def setUp(self):
        super(WhenUsingTaskServer, self).setUp()

        self.target = 'a target value here'
        queue.get_target = mock.MagicMock(return_value=self.target)

        self.server_mock = mock.MagicMock()
        self.server_mock.start.return_value = None
        self.server_mock.stop.return_value = None

        queue.get_server = mock.MagicMock(return_value=self.server_mock)

        self.server = server.TaskServer()

    def test_should_start(self):
        self.server.start()
        queue.get_target.assert_called_with()
        queue.get_server.assert_called_with(target=self.target,
                                            endpoints=[self.server])
        self.server_mock.start.assert_called_with()

    def test_should_stop(self):
        self.server.stop()
        queue.get_target.assert_called_with()
        queue.get_server.assert_called_with(target=self.target,
                                            endpoints=[self.server])
        self.server_mock.stop.assert_called_with()
