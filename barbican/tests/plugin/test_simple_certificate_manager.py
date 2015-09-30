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

import testtools

import barbican.plugin.interface.certificate_manager as cm
import barbican.plugin.simple_certificate_manager as simple


class WhenTestingSimpleCertificateManagerPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingSimpleCertificateManagerPlugin, self).setUp()
        self.plugin = simple.SimpleCertificatePlugin()

    def test_issue_certificate_request(self):
        result = self.plugin.issue_certificate_request(None, None, None, None)

        self.assertEqual(cm.CertificateStatus.WAITING_FOR_CA, result.status)

    def test_check_certificate_status(self):
        result = self.plugin.check_certificate_status(None, None, None, None)

        self.assertEqual(
            cm.CertificateStatus.CERTIFICATE_GENERATED, result.status)

    def test_modify_certificate_request(self):
        result = self.plugin.modify_certificate_request(None, None, None, None)

        self.assertEqual(cm.CertificateStatus.WAITING_FOR_CA, result.status)

    def test_cancel_certificate_request(self):
        result = self.plugin.cancel_certificate_request(None, None, None, None)

        self.assertEqual(cm.CertificateStatus.REQUEST_CANCELED, result.status)

    def test_supports(self):
        result = self.plugin.supports(None)

        self.assertTrue(result)

    def test_get_ca_info(self):
        result = self.plugin.get_ca_info()
        name = self.plugin.get_default_ca_name()
        self.assertIn(name, result)
        self.assertEqual(name, result[name][cm.INFO_NAME])
        self.assertEqual(self.plugin.get_default_signing_cert(),
                         result[name][cm.INFO_CA_SIGNING_CERT])

    def test_supported_request_types(self):
        result = self.plugin.supported_request_types()
        supported_list = [cm.CertificateRequestType.CUSTOM_REQUEST,
                          cm.CertificateRequestType.SIMPLE_CMC_REQUEST,
                          cm.CertificateRequestType.FULL_CMC_REQUEST,
                          cm.CertificateRequestType.STORED_KEY_REQUEST]
        self.assertEqual(supported_list, result)


class WhenTestingSimpleCertificateEventManagerPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingSimpleCertificateEventManagerPlugin, self).setUp()
        self.plugin = simple.SimpleCertificateEventPlugin()

    def test_notify_ca_is_unavailable(self):
        # Test that eventing plugin method does not have side effects such as
        #   raising exceptions.
        self.plugin.notify_ca_is_unavailable(None, None, None, None)

    def test_notify_certificate_is_ready(self):
        # Test that eventing plugin method does not have side effects such as
        #   raising exceptions.
        self.plugin.notify_certificate_is_ready(None, None, None)
