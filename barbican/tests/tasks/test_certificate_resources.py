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

import mock
import testtools

from barbican.plugin.interface import certificate_manager as cert_man
from barbican.tasks import certificate_resources as cert_res


class WhenIssuingCertificateRequests(testtools.TestCase):

    def setUp(self):
        super(WhenIssuingCertificateRequests, self).setUp()
        self.order_id = "12345"
        self.order_meta = dict()
        self.plugin_meta = dict()
        self.result = cert_man.ResultDTO(
            cert_man.CertificateStatus.WAITING_FOR_CA
        )

        self.cert_plugin = mock.MagicMock()
        self.order_model = mock.MagicMock()
        self.order_model.id = self.order_id
        self.order_model.meta = self.order_meta
        self.repos = mock.MagicMock()
        self.tenant_model = mock.MagicMock()

        # Setting up mock data for the plugin manager.
        cert_plugin_config = {
            'return_value.get_plugin.return_value': self.cert_plugin
        }

        self.cert_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.CertificatePluginManager',
            **cert_plugin_config
        )
        self.cert_plugin_patcher.start()
        self.cert_plugin.issue_certificate_request.return_value = self.result

        # Setting up mock data for save plugin meta.
        self.save_plugin_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._save_plugin_metadata'
        )
        self.mock_save_plugin = self.save_plugin_meta_patcher.start()

        # Setting up mock data for get plugin meta.
        get_plugin_config = {'return_value': self.plugin_meta}
        self.get_plugin_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._get_plugin_meta',
            **get_plugin_config
        )
        self.get_plugin_meta_patcher.start()

    def tearDown(self):
        super(WhenIssuingCertificateRequests, self).tearDown()
        self.cert_plugin_patcher.stop()
        self.save_plugin_meta_patcher.stop()
        self.get_plugin_meta_patcher.stop()

    def test_should_return_waiting_for_ca(self):
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.tenant_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

    def test_should_return_certificate_generated(self):
        self.result.status = cert_man.CertificateStatus.CERTIFICATE_GENERATED

        cert_res.issue_certificate_request(self.order_model,
                                           self.tenant_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

    def test_should_raise_client_data_issue_seen(self):
        self.result.status = cert_man.CertificateStatus.CLIENT_DATA_ISSUE_SEEN

        self.assertRaises(
            cert_man.CertificateStatusClientDataIssue,
            cert_res.issue_certificate_request,
            self.order_model,
            self.tenant_model,
            self.repos
        )

    def test_should_return_ca_unavailable_for_request(self):
        self.result.status = (
            cert_man.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)

        cert_res.issue_certificate_request(self.order_model,
                                           self.tenant_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

    def test_should_raise_status_not_supported(self):
        self.result.status = "Legend of Link"

        self.assertRaises(
            cert_man.CertificateStatusNotSupported,
            cert_res.issue_certificate_request,
            self.order_model,
            self.tenant_model,
            self.repos
        )

    def _verify_issue_certificate_plugins_called(self):
        self.cert_plugin.issue_certificate_request.assert_called_once_with(
            self.order_id,
            self.order_meta,
            self.plugin_meta
        )

        self.mock_save_plugin.assert_called_once_with(
            self.order_model,
            self.plugin_meta,
            self.repos
        )
