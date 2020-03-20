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
from unittest import mock

from barbican import queue
from barbican.queue import client
from barbican.tests import utils


class WhenUsingAsyncTaskClient(utils.BaseTestCase):
    """Test using the asynchronous task client."""

    def setUp(self):
        super(WhenUsingAsyncTaskClient, self).setUp()

        # Mock out the queue get_client() call:
        self.mock_client = mock.MagicMock()
        self.mock_client.cast.return_value = None
        get_client_config = {
            'return_value': self.mock_client
        }
        self.get_client_patcher = mock.patch(
            'barbican.queue.get_client',
            **get_client_config
        )
        self.get_client_patcher.start()

        self.client = client.TaskClient()

    def tearDown(self):
        super(WhenUsingAsyncTaskClient, self).tearDown()
        self.get_client_patcher.stop()

    def test_should_process_type_order(self):
        self.client.process_type_order(order_id=self.order_id,
                                       project_id=self.external_project_id,
                                       request_id=self.request_id)
        self.mock_client.cast.assert_called_with(
            {}, 'process_type_order', order_id=self.order_id,
            project_id=self.external_project_id,
            request_id=self.request_id)


class WhenCreatingDirectTaskClient(utils.BaseTestCase):
    """Test using the synchronous task client (i.e. standalone mode)."""

    def setUp(self):
        super(WhenCreatingDirectTaskClient, self).setUp()

        queue.get_client = mock.MagicMock(return_value=None)

        self.client = client.TaskClient()

    def test_should_use_direct_task_client(self):
        self.assertIsInstance(self.client._client,
                              client._DirectTaskInvokerClient)
