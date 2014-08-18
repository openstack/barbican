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
import testtools

from barbican.plugin.interface import certificate_manager as cm


class WhenTestingCertificateEventPluginManager(testtools.TestCase):

    def setUp(self):
        super(WhenTestingCertificateEventPluginManager, self).setUp()

        self.project_id = '1234'
        self.order_ref = 'http://www.mycerts.com/v1/orders/123456'
        self.container_ref = 'http://www.mycerts.com/v1/containers/654321'
        self.error_msg = 'Something is broken'
        self.retry_in_msec = 5432

        self.plugin_returned = mock.MagicMock()
        self.plugin_name = 'mock.MagicMock'
        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)
        self.manager = cm.EVENT_PLUGIN_MANAGER
        self.manager.extensions = [self.plugin_loaded]

    def test_get_plugin_by_name(self):
        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin_by_name(self.plugin_name))

    def test_notify_ca_is_unavailable(self):
        self.manager.notify_ca_is_unavailable(
            self.project_id,
            self.order_ref,
            self.error_msg,
            self.retry_in_msec)

        self.plugin_returned.notify_ca_is_unavailable.assert_called_once_with(
            self.project_id,
            self.order_ref,
            self.error_msg,
            self.retry_in_msec)

    def test_notify_certificate_is_ready(self):
        self.manager.notify_certificate_is_ready(
            self.project_id,
            self.order_ref,
            self.container_ref)

        pr = self.plugin_returned
        pr.notify_certificate_is_ready.assert_called_once_with(
            self.project_id,
            self.order_ref,
            self.container_ref)

    def test_invoke_certificate_plugins(self):
        self.manager._invoke_certificate_plugins(
            'test_invoke_certificate_plugins',
            self.project_id,
            self.order_ref,
            self.container_ref)

        # The _invoke_certificate_plugins method should invoke on
        #   self.plugin_returned the same method by name as the function
        #   that invoked it...in this case it is this test method.
        pr = self.plugin_returned
        pr.test_invoke_certificate_plugins.assert_called_once_with(
            self.project_id,
            self.order_ref,
            self.container_ref)

    def test_raises_error_with_no_plugin_by_name_found(self):
        self.manager.extensions = []
        self.assertRaises(
            cm.CertificateEventPluginNotFound,
            self.manager.get_plugin_by_name,
            'any-name-here'
        )

    def test_raises_error_with_no_plugin_for_invoke_certificate_plugins(self):
        self.manager.extensions = []
        self.assertRaises(
            cm.CertificateEventPluginNotFound,
            self.manager._invoke_certificate_plugins,
            self.project_id,
            self.order_ref,
            self.error_msg,
            self.retry_in_msec,
        )
