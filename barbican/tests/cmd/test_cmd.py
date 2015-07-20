# Copyright (c) 2015 Rackspace, Inc.
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

from barbican.cmd import retry_scheduler
from barbican.tests import utils


class WhenInvokingRetryServiceCommand(utils.BaseTestCase):
    """Test the retry scheduler functionality."""

    def setUp(self):
        super(WhenInvokingRetryServiceCommand, self).setUp()

    @mock.patch('barbican.common.config')
    @mock.patch('barbican.queue.init')
    @mock.patch('oslo_service.service.launch')
    @mock.patch('barbican.queue.retry_scheduler.PeriodicServer')
    def test_should_launch_service(
            self,
            mock_periodic_server,
            mock_service_launch,
            mock_queue_init,
            mock_config):

        retry_scheduler.main()

        self.assertEqual(mock_queue_init.call_count, 1)
        self.assertEqual(mock_service_launch.call_count, 1)
        self.assertEqual(mock_periodic_server.call_count, 1)

    @mock.patch('oslo_log.log.setup')
    @mock.patch('sys.exit')
    def test_should_fail_run_command(
            self, mock_sys_exit, mock_log_setup):
        mock_log_setup.side_effect = RuntimeError()

        retry_scheduler.main()

        self.assertEqual(mock_sys_exit.call_count, 1)
