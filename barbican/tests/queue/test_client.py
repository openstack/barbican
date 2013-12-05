# Copyright (c) 2013 Rackspace, Inc.
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
import mock

from barbican import queue
from barbican.queue import client
from barbican.tests import utils


class WhenUsingAsyncTaskClient(utils.BaseTestCase):
    """Test using the asynchronous task client."""

    def setUp(self):
        super(WhenUsingAsyncTaskClient, self).setUp()

        self.mock_client = mock.MagicMock()
        self.mock_client.cast.return_value = None

        queue.get_client = mock.MagicMock(return_value=self.mock_client)

        self.client = client.TaskClient()

    def test_should_process_order(self):
        self.client.process_order(order_id=self.order_id,
                                  keystone_id=self.keystone_id)
        queue.get_client.assert_called_with()
        self.mock_client.cast.assert_called_with({}, 'process_order',
                                                 order_id=self.order_id,
                                                 keystone_id=self.keystone_id)

    def test_should_process_verification(self):
        self.client.process_verification(verification_id=self.verification_id,
                                         keystone_id=self.keystone_id)
        queue.get_client.assert_called_with()
        self.mock_client.cast.assert_called_with({}, 'process_verification',
                                                 verification_id=
                                                 self.verification_id,
                                                 keystone_id=self.keystone_id)


class WhenCreatingDirectTaskClient(utils.BaseTestCase):
    """Test using the synchronous task client (i.e. standalone mode)."""

    def setUp(self):
        super(WhenCreatingDirectTaskClient, self).setUp()

        queue.get_client = mock.MagicMock(return_value=None)

        self.client = client.TaskClient()

    def test_should_use_direct_task_client(self):
        self.assertIsInstance(self.client._client,
                              client._DirectTaskInvokerClient)
