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

import testtools
from unittest import mock

try:
    import barbican.plugin.interface.certificate_manager as cm
    import barbican.plugin.symantec as sym
    imports_ok = True
except ImportError:
    # Symantec imports probably not available
    imports_ok = False

from barbican.tests import utils


@testtools.skipIf(not imports_ok, "Symantec imports not available")
class WhenTestingSymantecPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSymantecPlugin, self).setUp()
        self.order_meta = {
            'cert_type': 'ssl123',
            'organization': 'Shinra Corp',
            'phone': '555-555-5555',
            'so many things...': 'more...'
        }

        self.error_msg = 'Error Message Here'
        self.symantec = sym.SymantecCertificatePlugin()
        self.barbican_plugin_dto = cm.BarbicanMetaDTO()

        self.symantec_patcher = mock.patch(
            'barbican.plugin.symantec._ca_create_order'
        )
        self.mock_create_order = self.symantec_patcher.start()

    def tearDown(self):
        super(WhenTestingSymantecPlugin, self).tearDown()
        if hasattr(self, 'mock_create_order'):
            self.mock_create_order.stop()

    def test_successful_issue_certificate_request(self):
        self.mock_create_order.return_value = (True, None, None)

        order_id = '1234'
        plugin_meta = {}

        result = self.symantec.issue_certificate_request(
            order_id,
            self.order_meta,
            plugin_meta,
            self.barbican_plugin_dto
        )

        self.assertEqual("waiting for CA", result.status)

    def test_unsuccessful_certificate_request_can_retry(self):
        self.mock_create_order.return_value = (False, self.error_msg, True)

        order_id = '1234'
        plugin_meta = {}

        result = self.symantec.issue_certificate_request(
            order_id,
            self.order_meta,
            plugin_meta,
            self.barbican_plugin_dto
        )

        self.assertEqual("client data issue seen", result.status)

    def test_unsuccessful_certificate_request_no_retry(self):
        self.mock_create_order.return_value = (False, self.error_msg, False)

        order_id = '12345'
        plugin_meta = {}

        result = self.symantec.issue_certificate_request(
            order_id,
            self.order_meta,
            plugin_meta,
            self.barbican_plugin_dto
        )

        self.assertEqual("CA unavailable for request", result.status)

    def test_should_raise_unsupported_certificate_request(self):
        order_id = '1234'
        plugin_meta = {}
        self.assertRaises(
            NotImplementedError,
            self.symantec.check_certificate_status,
            order_id,
            self.order_meta,
            plugin_meta,
            self.barbican_plugin_dto
        )
