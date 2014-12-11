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

from barbican.common import hrefs
from barbican.plugin.interface import certificate_manager as cert_man
from barbican.tasks import certificate_resources as cert_res
from barbican.tests import utils


class WhenPerformingPrivateOperations(utils.BaseTestCase):
    """Tests private methods within certificate_resources.py."""

    def test_get_plugin_meta(self):
        class Value(object):
            def __init__(self, value):
                self.value = value

        class OrderModel(object):
            id = mock.ANY
            order_plugin_metadata = {
                "foo": Value(1),
                "bar": Value(2),
            }
        order_model = OrderModel()
        repos = mock.MagicMock()
        meta_repo_mock = mock.MagicMock()
        repos.order_plugin_meta_repo = meta_repo_mock
        meta_repo_mock.get_metadata_for_order.return_value = (
            order_model.order_plugin_metadata
        )

        result = cert_res._get_plugin_meta(order_model, repos)

        self._assert_dict_equal(order_model.order_plugin_metadata, result)

    def test_get_plugin_meta_with_empty_dict(self):
        repos = mock.MagicMock()
        result = cert_res._get_plugin_meta(None, repos)

        self._assert_dict_equal({}, result)

    def test_save_plugin_meta(self):
        class Repo(object):
            plugin_meta = None
            order_model = None

            def save(self, plugin_meta, order_model):
                self.plugin_meta = plugin_meta
                self.order_model = order_model

        class Repos(object):
            def __init__(self, repo):
                self.order_plugin_meta_repo = repo

        test_repo = Repo()
        repos = Repos(test_repo)

        # Test dict for plugin meta data.
        test_order_model = 'My order model'
        test_plugin_meta = {"foo": 1}

        cert_res._save_plugin_metadata(
            test_order_model, test_plugin_meta, repos)

        self._assert_dict_equal(test_plugin_meta, test_repo.plugin_meta)
        self.assertEqual(test_order_model, test_repo.order_model)

        # Test None for plugin meta data.
        cert_res._save_plugin_metadata(
            test_order_model, None, repos)

        self._assert_dict_equal({}, test_repo.plugin_meta)

    def _assert_dict_equal(self, expected, test):
        self.assertIsInstance(expected, dict)
        self.assertIsInstance(test, dict)

        if expected != test:
            if len(expected) != len(test):
                self.fail('Expected dict not same size as test dict')

            unmatched_items = set(expected.items()) ^ set(test.items())
            if len(unmatched_items):
                self.fail('One or more items different '
                          'between the expected and test dicts')


class WhenIssuingCertificateRequests(utils.BaseTestCase):
    """Tests the 'issue_certificate_request()' function."""

    def setUp(self):
        super(WhenIssuingCertificateRequests, self).setUp()
        self.project_id = "56789"
        self.order_id = "12345"
        self.order_meta = dict()
        self.plugin_meta = dict()
        self.result = cert_man.ResultDTO(
            cert_man.CertificateStatus.WAITING_FOR_CA
        )

        self.cert_plugin = mock.MagicMock()
        self.cert_plugin.issue_certificate_request.return_value = self.result

        self.order_model = mock.MagicMock()
        self.order_model.id = self.order_id
        self.order_model.meta = self.order_meta
        self.order_model.project_id = self.project_id
        self.repos = mock.MagicMock()
        self.project_model = mock.MagicMock()

        self._config_cert_plugin()
        self._config_cert_event_plugin()
        self._config_save_meta_plugin()
        self._config_get_meta_plugin()

    def tearDown(self):
        super(WhenIssuingCertificateRequests, self).tearDown()
        self.cert_plugin_patcher.stop()
        self.save_plugin_meta_patcher.stop()
        self.get_plugin_meta_patcher.stop()
        self.cert_event_plugin_patcher.stop()

    def test_should_return_waiting_for_ca(self):
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

    def test_should_return_certificate_generated(self):
        self.result.status = cert_man.CertificateStatus.CERTIFICATE_GENERATED

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

    def test_should_raise_client_data_issue_seen(self):
        self.result.status = cert_man.CertificateStatus.CLIENT_DATA_ISSUE_SEEN

        self.assertRaises(
            cert_man.CertificateStatusClientDataIssue,
            cert_res.issue_certificate_request,
            self.order_model,
            self.project_model,
            self.repos
        )

    def test_should_raise_invalid_operation_seen(self):
        self.result.status = cert_man.CertificateStatus.INVALID_OPERATION

        self.assertRaises(
            cert_man.CertificateStatusInvalidOperation,
            cert_res.issue_certificate_request,
            self.order_model,
            self.project_model,
            self.repos
        )

    def test_should_return_ca_unavailable_for_request(self):
        retry_msec = 123
        status_msg = 'Test status'
        self.result.status = (
            cert_man.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)
        self.result.retry_msec = retry_msec
        self.result.status_message = status_msg
        order_ref = hrefs.convert_order_to_href(self.order_id)

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model,
                                           self.repos)

        self._verify_issue_certificate_plugins_called()

        epm = self.cert_event_plugin_patcher.target.EVENT_PLUGIN_MANAGER
        epm.notify_ca_is_unavailable.assert_called_once_with(
            self.project_id,
            order_ref,
            status_msg,
            retry_msec
        )

    def test_should_raise_status_not_supported(self):
        self.result.status = "Legend of Link"

        self.assertRaises(
            cert_man.CertificateStatusNotSupported,
            cert_res.issue_certificate_request,
            self.order_model,
            self.project_model,
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

    def _config_cert_plugin(self):
        """Mock the certificate plugin manager."""
        cert_plugin_config = {
            'return_value.get_plugin.return_value': self.cert_plugin
        }
        self.cert_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.CertificatePluginManager',
            **cert_plugin_config
        )
        self.cert_plugin_patcher.start()

    def _config_cert_event_plugin(self):
        """Mock the certificate event plugin manager."""
        self.cert_event_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.EVENT_PLUGIN_MANAGER'
        )
        self.cert_event_plugin_patcher.start()

    def _config_save_meta_plugin(self):
        """Mock the save plugin meta function."""
        self.save_plugin_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._save_plugin_metadata'
        )
        self.mock_save_plugin = self.save_plugin_meta_patcher.start()

    def _config_get_meta_plugin(self):
        """Mock the get plugin meta function."""
        get_plugin_config = {'return_value': self.plugin_meta}
        self.get_plugin_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._get_plugin_meta',
            **get_plugin_config
        )
        self.get_plugin_meta_patcher.start()
