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
import testtools

from barbican.common import utils as common_utils
from barbican.model import models
from barbican.plugin.interface import certificate_manager as cm
from barbican.tests import database_utils
from barbican.tests import utils


class WhenTestingCertificateEventPluginManager(testtools.TestCase):

    def setUp(self):
        super(WhenTestingCertificateEventPluginManager, self).setUp()

        self.project_id = '1234'
        self.order_ref = 'http://www.mycerts.com/v1/orders/123456'
        self.container_ref = 'http://www.mycerts.com/v1/containers/654321'
        self.error_msg = 'Something is broken'
        self.retry_in_msec = 5432

        self.plugin_returned = mock.MagicMock()
        self.plugin_name = common_utils.generate_fullname_for(
            self.plugin_returned)
        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)
        self.manager = cm.get_event_plugin_manager()
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


class WhenTestingCertificatePluginManager(database_utils.RepositoryTestCase,
                                          utils.MockModelRepositoryMixin):

    def setUp(self):
        super(WhenTestingCertificatePluginManager, self).setUp()
        self.cert_spec = {}

        self.plugin_returned = mock.MagicMock()
        self.plugin_name = common_utils.generate_fullname_for(
            self.plugin_returned)
        types_list = [cm.CertificateRequestType.SIMPLE_CMC_REQUEST,
                      cm.CertificateRequestType.CUSTOM_REQUEST]
        self.plugin_returned.supported_request_types.return_value = types_list
        self.plugin_returned.supports.return_value = True
        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)

        expiration = (datetime.datetime.utcnow() + datetime.timedelta(
            days=cm.CA_INFO_DEFAULT_EXPIRATION_DAYS))
        ca_info = {
            cm.INFO_NAME: "my_ca",
            cm.INFO_DESCRIPTION: "Certificate Authority my_ca",
            cm.INFO_CA_SIGNING_CERT: "Undefined",
            cm.INFO_INTERMEDIATES: "Undefined",
            cm.INFO_EXPIRATION: expiration.isoformat()
        }
        self.plugin_returned.get_ca_info.return_value = {
            'plugin_ca_id1': ca_info
        }

        parsed_ca = {
            'plugin_name': self.plugin_name,
            'plugin_ca_id': 'plugin_ca_id1',
            'name': self.plugin_name,
            'description': 'Master CA for default plugin',
            'ca_signing_certificate': 'ZZZZZ',
            'intermediates': 'YYYYY'
        }
        self.ca = models.CertificateAuthority(parsed_ca)
        self.ca.id = 'ca_id'

        self.ca_repo = mock.MagicMock()
        self.ca_repo.get_by_create_date.return_value = (
            self.ca, 0, 1, 1)
        self.ca_repo.create_from.return_value = None
        self.ca_repo.get.return_value = self.ca

        self.project = models.Project()
        self.project.id = '12345'

        self.setup_ca_repository_mock(self.ca_repo)

        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)
        self.manager = cm.CertificatePluginManager()
        self.manager.extensions = [self.plugin_loaded]

    def test_get_plugin_by_name(self):
        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin_by_name(self.plugin_name))

    def test_get_plugin_by_ca_id(self):
        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin_by_ca_id('ca_id'))

    def test_raises_error_with_no_plugin_by_ca_id_found(self):
        self.ca_repo.get.return_value = None
        self.assertRaises(
            cm.CertificatePluginNotFoundForCAID,
            self.manager.get_plugin_by_ca_id,
            'any-name-here'
        )

    def test_raises_error_with_no_plugin_by_name_found(self):
        self.manager.extensions = []
        self.assertRaises(
            cm.CertificatePluginNotFound,
            self.manager.get_plugin_by_name,
            'any-name-here'
        )

    def test_get_plugin_no_request_type_provided(self):
        # no request_type defaults to "custom"
        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin(self.cert_spec))

    def test_get_plugin_request_type_supported(self):
        self.cert_spec = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.SIMPLE_CMC_REQUEST}
        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin(self.cert_spec))

    def test_raises_error_get_plugin_request_type_not_supported(self):
        self.cert_spec = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.FULL_CMC_REQUEST}
        self.assertRaises(
            cm.CertificatePluginNotFound,
            self.manager.get_plugin,
            self.cert_spec
        )

    def test_raises_error_with_no_plugin_found(self):
        self.manager.extensions = []
        self.assertRaises(
            cm.CertificatePluginNotFound,
            self.manager.get_plugin,
            self.cert_spec
        )

    def test_get_plugin_with_ca_to_be_added(self):
        self.ca_repo.get_by_create_date.return_value = (
            None, 0, 1, 0)

        self.assertEqual(self.plugin_returned,
                         self.manager.get_plugin(self.cert_spec))

    def test_refresh_ca_list(self):
        utc_now = datetime.datetime.utcnow()
        expired_time = utc_now - datetime.timedelta(days=1)
        expiration = utc_now + datetime.timedelta(days=1)

        ca1_info = {
            cm.INFO_NAME: "expired_ca_to_be_modified",
            cm.INFO_DESCRIPTION: "expired_ca to be modified",
            cm.INFO_CA_SIGNING_CERT: "XXXXXXX-expired-XXXXXX",
            cm.INFO_INTERMEDIATES: "YYYYYYY-expired-YYYYYYY",
            cm.INFO_EXPIRATION: expired_time.isoformat()
        }

        ca1_modified_info = {
            cm.INFO_NAME: "expired_ca_to_be_modified",
            cm.INFO_DESCRIPTION: "expired_ca to be modified",
            cm.INFO_CA_SIGNING_CERT: "XXXXXXX-no-longer-expired-XXXXXX",
            cm.INFO_INTERMEDIATES: "YYYYYYY-no-longer-expired-YYYYYYY",
            cm.INFO_EXPIRATION: expiration.isoformat()
        }

        ca2_info = {
            cm.INFO_NAME: "expired_ca_to_be_deleted",
            cm.INFO_DESCRIPTION: "expired ca to be deleted",
            cm.INFO_CA_SIGNING_CERT: "XXXX-expired-to-be-deleted-XXXX",
            cm.INFO_INTERMEDIATES: "YYYY-expired-to-be-deleted-YYYY",
            cm.INFO_EXPIRATION: expired_time.isoformat()
        }

        ca3_info = {
            cm.INFO_NAME: "new-ca-to-be-added",
            cm.INFO_DESCRIPTION: "new-ca-to-be-added",
            cm.INFO_CA_SIGNING_CERT: "XXXX-to-be-addeed-XXXX",
            cm.INFO_INTERMEDIATES: "YYYY-to-be-added-YYYY",
            cm.INFO_EXPIRATION: expiration.isoformat()
        }

        self.plugin_returned.get_ca_info.return_value = {
            'plugin_ca_id_ca1': ca1_modified_info,
            'plugin_ca_id_ca3': ca3_info
        }

        parsed_ca1 = dict(ca1_info)
        parsed_ca1[cm.PLUGIN_CA_ID] = 'plugin_ca_id_ca1'
        parsed_ca1['plugin_name'] = self.plugin_name
        ca1 = models.CertificateAuthority(parsed_ca1)
        ca1.id = "ca1_id"

        parsed_ca2 = dict(ca2_info)
        parsed_ca2[cm.PLUGIN_CA_ID] = 'plugin_ca_id_ca2'
        parsed_ca2['plugin_name'] = self.plugin_name
        ca2 = models.CertificateAuthority(parsed_ca2)
        ca2.id = "ca2_id"

        side_effect = [(None, 0, 4, 0),
                       ([ca1, ca2], 0, 4, 2)]
        self.ca_repo.get_by_create_date.side_effect = side_effect

        self.manager.refresh_ca_table()
        self.plugin_returned.get_ca_info.assert_called_once_with()
        self.ca_repo.update_entity.assert_called_once_with(
            ca1,
            ca1_modified_info)

        self.ca_repo.delete_entity_by_id.assert_called_once_with(
            ca2.id,
            None)
        self.ca_repo.create_from.assert_has_calls([])

    def test_refresh_ca_list_plugin_when_get_ca_info_raises(self):
        self.ca_repo.get_by_create_date.return_value = (None, 0, 4, 0)
        self.plugin_returned.get_ca_info.side_effect = Exception()

        self.manager.refresh_ca_table()

        self.plugin_returned.get_ca_info.assert_called_once_with()

    def test_refresh_ca_list_with_bad_ca_returned_from_plugin(self):

        ca3_info = {
            cm.INFO_DESCRIPTION: "PLUGIN FAIL: this-ca-has-no-info",
        }

        self.plugin_returned.get_ca_info.return_value = {
            'plugin_ca_id_ca3': ca3_info
        }

        self.ca_repo.get_by_create_date.return_value = (None, 0, 4, 0)
        self.ca_repo.create_from.side_effect = Exception()

        self.manager.refresh_ca_table()

        self.plugin_returned.get_ca_info.assert_called_once_with()
        self.ca_repo.create_from.assert_has_calls([])
