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

from Crypto.PublicKey import RSA
import mock
from OpenSSL import crypto

from barbican.common import exception as excep
from barbican.common import hrefs
from barbican.model import models
from barbican.plugin.interface import certificate_manager as cert_man
from barbican.tasks import certificate_resources as cert_res
from barbican.tests import utils


class WhenPerformingPrivateOperations(utils.BaseTestCase,
                                      utils.MockModelRepositoryMixin):
    """Tests private methods within certificate_resources.py."""

    def setUp(self):
        super(WhenPerformingPrivateOperations, self).setUp()
        self.order_plugin_meta_repo = mock.MagicMock()
        self.setup_order_plugin_meta_repository_mock(
            self.order_plugin_meta_repo)

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
        self.order_plugin_meta_repo.get_metadata_for_order.return_value = (
            order_model.order_plugin_metadata
        )
        result = cert_res._get_plugin_meta(order_model)

        self._assert_dict_equal(order_model.order_plugin_metadata, result)

    def test_get_plugin_meta_with_empty_dict(self):
        result = cert_res._get_plugin_meta(None)

        self._assert_dict_equal({}, result)

    def test_save_plugin_meta_w_mock_meta(self):
        # Test dict for plugin meta data.
        test_order_model = 'My order model'
        test_plugin_meta = {"foo": 1}

        cert_res._save_plugin_metadata(
            test_order_model, test_plugin_meta)

        self.order_plugin_meta_repo.save.assert_called_once_with(
            test_plugin_meta, test_order_model)

    def test_save_plugin_w_null_meta(self):
        test_order_model = 'My order model'

        # Test None for plugin meta data.
        cert_res._save_plugin_metadata(
            test_order_model, None)

        self.order_plugin_meta_repo.save.assert_called_once_with(
            {}, test_order_model)

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


class WhenIssuingCertificateRequests(utils.BaseTestCase,
                                     utils.MockModelRepositoryMixin):
    """Tests the 'issue_certificate_request()' function."""

    def setUp(self):
        super(WhenIssuingCertificateRequests, self).setUp()
        self.project_id = "56789"
        self.order_id = "12345"
        self.barbican_meta_dto = mock.MagicMock()
        self.order_meta = {}
        self.plugin_meta = {}
        self.barbican_meta = {}
        self.result = cert_man.ResultDTO(
            cert_man.CertificateStatus.WAITING_FOR_CA
        )

        self.cert_plugin = mock.MagicMock()
        self.cert_plugin.issue_certificate_request.return_value = self.result

        self.order_model = mock.MagicMock()
        self.order_model.id = self.order_id
        self.order_model.meta = self.order_meta
        self.order_model.project_id = self.project_id
        self.order_model.order_barbican_meta = self.barbican_meta
        self.project_model = mock.MagicMock()

        self._config_cert_plugin()
        self._config_cert_event_plugin()
        self._config_save_meta_plugin()
        self._config_get_meta_plugin()
        self._config_barbican_meta_dto()

        self.private_key_secret_id = "private_key_secret_id"
        self.public_key_secret_id = "public_key_secret_id"
        self.passphrase_secret_id = "passphrase_secret_id"
        self.private_key_value = None
        self.public_key_value = "my public key"
        self.passphrase_value = "my passphrase"

        self.container_id = "container_id"
        self.parsed_container_with_passphrase = {
            'name': 'container name',
            'type': 'asymmetric',
            'secret_refs': [
                {'name': 'private_key',
                 'secret_ref':
                 'https://localhost/secrets/' + self.private_key_secret_id},
                {'name': 'public_key',
                 'secret_ref':
                 'https://localhost/secrets/' + self.public_key_secret_id},
                {'name': 'private_key_passphrase',
                 'secret_ref':
                 'https://localhost/secrets/' + self.passphrase_secret_id}
            ]}

        self.parsed_container_without_passphrase = {
            'name': 'container name',
            'type': 'asymmetric',
            'secret_refs': [
                {'name': 'private_key',
                 'secret_ref':
                 'https://localhost/secrets/' + self.private_key_secret_id},
                {'name': 'public_key',
                 'secret_ref':
                 'https://localhost/secrets/' + self.public_key_secret_id},
            ]}

        self.stored_key_meta = {
            cert_man.REQUEST_TYPE:
            cert_man.CertificateRequestType.STORED_KEY_REQUEST,
            "container_ref":
            "https://localhost/containers/" + self.container_id,
            "subject_name": "cn=host.example.com,ou=dev,ou=us,o=example.com"
        }
        self.order_model.order_barbican_metadata = {}

        # Set up mocked repos
        self.container_repo = mock.MagicMock()
        self.secret_repo = mock.MagicMock()
        self.ca_repo = mock.MagicMock()
        self.preferred_ca_repo = mock.MagicMock()

        self.preferred_ca_repo.get_by_create_date.return_value = (
            None, 0, 10, 0)
        self.preferred_ca_repo.get_global_preferred_ca.return_value = None

        self.pref_ca = models.PreferredCertificateAuthority(
            self.project_id,
            "ca_id")

        # Set up mocked repositories
        self.setup_container_repository_mock(self.container_repo)
        self.setup_container_secret_repository_mock()
        self.setup_order_plugin_meta_repository_mock()
        self.setup_project_secret_repository_mock()
        self.setup_secret_repository_mock(self.secret_repo)
        self.setup_ca_repository_mock(self.ca_repo)
        self.setup_preferred_ca_repository_mock(self.preferred_ca_repo)

    def stored_key_side_effect(self, *args, **kwargs):
        if args[0] == self.private_key_secret_id:
            return self.private_key_value
        elif args[0] == self.public_key_secret_id:
            return self.public_key_value
        elif args[0] == self.passphrase_secret_id:
            return self.passphrase_value
        else:
            return None

    def tearDown(self):
        super(WhenIssuingCertificateRequests, self).tearDown()
        self.cert_plugin_patcher.stop()
        self.save_plugin_meta_patcher.stop()
        self.get_plugin_meta_patcher.stop()
        self.cert_event_plugin_patcher.stop()
        self.barbican_meta_dto_patcher.stop()

    def test_should_return_waiting_for_ca(self):
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()

    def test_should_return_certificate_generated(self):
        self.result.status = cert_man.CertificateStatus.CERTIFICATE_GENERATED

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()

    def test_should_raise_client_data_issue_seen(self):
        self.result.status = cert_man.CertificateStatus.CLIENT_DATA_ISSUE_SEEN

        self.assertRaises(
            cert_man.CertificateStatusClientDataIssue,
            cert_res.issue_certificate_request,
            self.order_model,
            self.project_model
        )

    def _do_pyopenssl_stored_key_request(self):
        self.container = models.Container(
            self.parsed_container_without_passphrase)
        self.container_repo.get.return_value = self.container

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        self.private_key_value = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey)

        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)

        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

    def test_should_return_for_pyopenssl_stored_key(self):
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_openssl_stored_key_ca_id_passed_in(self):
        self.stored_key_meta['ca_id'] = "ca1"
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

    def test_should_return_for_openssl_stored_key_pref_ca_defined(self):
        self.preferred_ca_repo.get_by_create_date.return_value = (
            [self.pref_ca], 0, 10, 1)
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

    def test_should_return_for_openssl_stored_key_global_ca_defined(self):
        self.preferred_ca_repo.get_global_preferred_ca.return_value = (
            self.pref_ca
        )
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

    def test_should_return_for_pyopenssl_stored_key_with_passphrase(self):
        self.container = models.Container(
            self.parsed_container_with_passphrase)
        self.container_repo.get.return_value = self.container

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        self.private_key_value = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey, passphrase=self.passphrase_value)

        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)

        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_pycrypto_stored_key_with_passphrase(self):
        self.container = models.Container(
            self.parsed_container_with_passphrase)
        self.container_repo.get.return_value = self.container

        private_key = RSA.generate(2048, None, None, 65537)
        public_key = private_key.publickey()

        self.private_key_value = private_key.exportKey(
            'PEM', self.passphrase_value, 8)
        self.public_key_value = public_key.exportKey()
        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_pycrypto_stored_key_without_passphrase(self):
        self.container = models.Container(
            self.parsed_container_without_passphrase)
        self.container_repo.get.return_value = self.container

        private_key = RSA.generate(2048, None, None, 65537)
        public_key = private_key.publickey()

        self.private_key_value = private_key.exportKey('PEM', None, 8)
        self.public_key_value = public_key.exportKey()
        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_raise_for_pycrypto_stored_key_no_container(self):
        self.container = models.Container(
            self.parsed_container_without_passphrase)
        self.container_repo.get.return_value = None

        private_key = RSA.generate(2048, None, None, 65537)
        public_key = private_key.publickey()

        self.private_key_value = private_key.exportKey('PEM', None, 8)
        self.public_key_value = public_key.exportKey()
        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        self.assertRaises(excep.StoredKeyContainerNotFound,
                          cert_res.issue_certificate_request,
                          self.order_model,
                          self.project_model)

    def test_should_raise_for_pycrypto_stored_key_no_private_key(self):
        self.container = models.Container(
            self.parsed_container_without_passphrase)
        self.container_repo.get.return_value = self.container

        private_key = RSA.generate(2048, None, None, 65537)
        public_key = private_key.publickey()

        self.private_key_value = private_key.exportKey('PEM', None, 8)
        self.public_key_value = public_key.exportKey()
        self.secret_repo.get.return_value = None

        self.order_meta.update(self.stored_key_meta)
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        self.assertRaises(excep.StoredKeyPrivateKeyNotFound,
                          cert_res.issue_certificate_request,
                          self.order_model,
                          self.project_model)

    def test_should_return_for_pyopenssl_stored_key_with_extensions(self):
        self.container = models.Container(
            self.parsed_container_without_passphrase)
        self.container_repo.get.return_value = self.container

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        self.private_key_value = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey)

        self.secret_repo.get.side_effect = self.stored_key_side_effect

        self.order_meta.update(self.stored_key_meta)
        self.order_meta['extensions'] = 'my ASN.1 extensions structure here'
        # TODO(alee-3) Add real extensions data here

        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order_model,
                                           self.project_model)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order_model.order_barbican_metadata['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.
        # TODO(alee-3) Add tests to validate the extensions in the request

    def test_should_raise_invalid_operation_seen(self):
        self.result.status = cert_man.CertificateStatus.INVALID_OPERATION

        self.assertRaises(
            cert_man.CertificateStatusInvalidOperation,
            cert_res.issue_certificate_request,
            self.order_model,
            self.project_model
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
                                           self.project_model)

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
            self.project_model
        )

    def _verify_issue_certificate_plugins_called(self):
        self.cert_plugin.issue_certificate_request.assert_called_once_with(
            self.order_id,
            self.order_meta,
            self.plugin_meta,
            self.barbican_meta_dto
        )

        self.mock_save_plugin.assert_called_once_with(
            self.order_model,
            self.plugin_meta
        )

    def _config_cert_plugin(self):
        """Mock the certificate plugin manager."""
        cert_plugin_config = {
            'return_value.get_plugin.return_value': self.cert_plugin,
            'return_value.get_plugin_by_ca_id.return_value': self.cert_plugin
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

    def _config_barbican_meta_dto(self):
        """Mock the BarbicanMetaDTO."""
        get_plugin_config = {'return_value': self.barbican_meta_dto}
        self.barbican_meta_dto_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.BarbicanMetaDTO',
            **get_plugin_config
        )
        self.barbican_meta_dto_patcher.start()
