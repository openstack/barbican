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

from barbican import i18n as u
from barbican.tasks import common
from barbican.tests import utils


class WhenUsingFollowOnProcessingStatusDTO(utils.BaseTestCase):
    """Test using the :class:`WhenUsingFollowOnProcessingStatusDTO` class."""

    def setUp(self):
        super(WhenUsingFollowOnProcessingStatusDTO, self).setUp()

        self.target = common.FollowOnProcessingStatusDTO()

    def test_should_have_expected_defaults(self):
        self.assertEqual(
            common.RetryTasks.NO_ACTION_REQUIRED, self.target.retry_task)
        self.assertEqual(u._('Unknown'), self.target.status)
        self.assertEqual(u._('Unknown'), self.target.status_message)
        self.assertEqual(common.RETRY_MSEC_DEFAULT, self.target.retry_msec)
        self.assertFalse(self.target.is_follow_on_needed())

    def test_should_indicate_no_follow_on_with_no_retry_task(self):
        self.target.retry_task = None

        self.assertFalse(self.target.is_follow_on_needed())

    def test_should_indicate_follow_on_when_retry_task_provided(self):
        self.target.retry_task = common.RetryTasks.INVOKE_SAME_TASK

        self.assertTrue(self.target.is_follow_on_needed())
