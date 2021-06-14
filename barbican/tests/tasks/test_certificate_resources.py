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

import base64
import datetime
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from oslo_utils import encodeutils

from barbican.common import exception as excep
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.interface import certificate_manager as cert_man
from barbican.plugin.interface import secret_store
from barbican.tasks import certificate_resources as cert_res
from barbican.tasks import common
from barbican.tests import database_utils
from barbican.tests import utils

container_repo = repositories.get_container_repository()
secret_repo = repositories.get_secret_repository()
ca_repo = repositories.get_ca_repository()
project_ca_repo = repositories.get_project_ca_repository()
preferred_ca_repo = repositories.get_preferred_ca_repository()
project_repo = repositories.get_project_repository()
order_repo = repositories.get_order_repository()


class WhenPerformingPrivateOperations(utils.BaseTestCase,
                                      utils.MockModelRepositoryMixin):
    """Tests private methods within certificate_resources.py."""

    def setUp(self):
        super(WhenPerformingPrivateOperations, self).setUp()
        self.order_plugin_meta_repo = mock.MagicMock()
        self.setup_order_plugin_meta_repository_mock(
            self.order_plugin_meta_repo)
        self.order_barbican_meta_repo = mock.MagicMock()
        self.setup_order_barbican_meta_repository_mock(
            self.order_barbican_meta_repo)

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

    def test_get_barbican_meta_with_empty_dict(self):
        result = cert_res._get_barbican_meta(None)

        self._assert_dict_equal({}, result)

    def test_save_barbican_w_null_meta(self):
        test_order_model = 'My order model'

        # Test None for plugin meta data.
        cert_res._save_barbican_metadata(
            test_order_model, None)

        self.order_barbican_meta_repo.save.assert_called_once_with(
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


class BaseCertificateRequestsTestCase(database_utils.RepositoryTestCase):
    """Base Certificate Case Test function """

    def setUp(self):
        super(BaseCertificateRequestsTestCase, self).setUp()

        self.external_project_id = "56789"
        self.project = res.get_or_create_project(self.external_project_id)
        project_repo.save(self.project)

        self.barbican_meta_dto = mock.MagicMock()
        self.order_meta = {}
        self.plugin_meta = {}
        self.barbican_meta = {}
        self.result = cert_man.ResultDTO(
            cert_man.CertificateStatus.WAITING_FOR_CA
        )
        self.result_follow_on = common.FollowOnProcessingStatusDTO()

        self.cert_plugin = mock.MagicMock()
        self.cert_plugin.issue_certificate_request.return_value = self.result
        self.cert_plugin.check_certificate_status.return_value = self.result

        self.store_plugin = mock.MagicMock()

        parsed_ca = {
            'plugin_name': "cert_plugin",
            'plugin_ca_id': "XXXX",
            'name': "test ca",
            'description': 'Test CA',
            'ca_signing_certificate': 'ZZZZZ',
            'intermediates': 'YYYYY'
        }

        self.ca = models.CertificateAuthority(parsed_ca)
        ca_repo.create_from(self.ca)
        self.ca_id = self.ca.id

        # second ca for testing
        parsed_ca = {
            'plugin_name': "cert_plugin",
            'plugin_ca_id': "XXXX2",
            'name': "test ca2",
            'description': 'Test CA2',
            'ca_signing_certificate': 'ZZZZZ2',
            'intermediates': 'YYYYY2'
        }

        self.ca2 = models.CertificateAuthority(parsed_ca)
        ca_repo.create_from(self.ca2)
        self.ca_id2 = self.ca2.id

        # data for preferred CA and global preferred CA tests
        # add those to the repo in those tests
        self.pref_ca = models.PreferredCertificateAuthority(
            self.project.id,
            self.ca_id)

        self.global_pref_ca = models.PreferredCertificateAuthority(
            self.project.id,
            self.ca_id)

        # data for stored key cases
        self.private_key = models.Secret()
        self.private_key.secret_type = 'PRIVATE'
        self.private_key.project_id = self.project.id
        secret_repo.create_from(self.private_key)

        self.public_key = models.Secret()
        self.public_key.secret_type = 'PUBLIC'
        self.public_key.project_id = self.project.id
        secret_repo.create_from(self.public_key)

        self.passphrase = models.Secret()
        self.passphrase.secret_type = 'PASSPHRASE'
        self.passphrase.project_id = self.project.id
        secret_repo.create_from(self.passphrase)

        self.private_key_value = None
        self.public_key_value = "public_key"
        self.passphrase_value = None

        self.parsed_container_with_passphrase = {
            'name': 'container name',
            'type': 'rsa',
            'secret_refs': [
                {'name': 'private_key',
                 'secret_ref': 'https://localhost/secrets/' +
                               self.private_key.id},
                {'name': 'public_key',
                 'secret_ref': 'https://localhost/secrets/' +
                               self.public_key.id},
                {'name': 'private_key_passphrase',
                 'secret_ref': 'https://localhost/secrets/' +
                               self.passphrase.id}
            ]
        }

        self.parsed_container = {
            'name': 'container name',
            'type': 'rsa',
            'secret_refs': [
                {'name': 'private_key',
                 'secret_ref': 'https://localhost/secrets/' +
                               self.private_key.id},
                {'name': 'public_key',
                 'secret_ref': 'https://localhost/secrets/' +
                               self.public_key.id}
            ]
        }

        self.container_with_passphrase = models.Container(
            self.parsed_container_with_passphrase)
        self.container_with_passphrase.project_id = self.project.id
        container_repo.create_from(self.container_with_passphrase)

        self.container = models.Container(self.parsed_container)
        self.container.project_id = self.project.id
        container_repo.create_from(self.container)

        repositories.commit()

        self.stored_key_meta = {
            cert_man.REQUEST_TYPE:
            cert_man.CertificateRequestType.STORED_KEY_REQUEST,
            "container_ref":
            "https://localhost/containers/" + self.container.id,
            "subject_dn": "cn=host.example.com,ou=dev,ou=us,o=example.com"
        }

        self.order = models.Order()
        self.order.meta = self.order_meta
        self.order.project_id = self.project.id
        self.order.order_barbican_meta = self.barbican_meta
        self.order.type = 'certificate'
        order_repo.create_from(self.order)

        self._config_cert_plugin()
        self._config_store_plugin()
        self._config_cert_event_plugin()
        self._config_save_meta_plugin()
        self._config_get_meta_plugin()
        self._config_save_barbican_meta_plugin()
        self._config_get_barbican_meta_plugin()
        self._config_barbican_meta_dto()

    def tearDown(self):
        super(BaseCertificateRequestsTestCase, self).tearDown()
        self.cert_plugin_patcher.stop()
        self.save_plugin_meta_patcher.stop()
        self.get_plugin_meta_patcher.stop()
        self.cert_event_plugin_patcher.stop()
        self.barbican_meta_dto_patcher.stop()
        self.save_barbican_barbican_meta_patcher.stop()
        self.get_barbican_plugin_meta_patcher.stop()
        self.store_plugin_patcher.stop()

    def stored_key_side_effect(self, *args, **kwargs):
        if args[0] == 'PRIVATE':
            return secret_store.SecretDTO(
                secret_store.SecretType.PRIVATE,
                self.private_key_value,
                None,
                'application/octet-string',
                None)
        elif args[0] == 'PASSPHRASE':
            return secret_store.SecretDTO(
                secret_store.SecretType.PASSPHRASE,
                self.passphrase_value,
                None,
                'application/octet-string',
                None)
        elif args[0] == 'PUBLIC':
            return secret_store.SecretDTO(
                secret_store.SecretType.PUBLIC,
                self.public_key_value,
                None,
                'application/octet-string',
                None)
        else:
            return None

    def _test_should_return_waiting_for_ca(self, method_to_test):
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        method_to_test(
            self.order, self.project, self.result_follow_on)

        self.assertEqual(
            common.RetryTasks.INVOKE_CERT_STATUS_CHECK_TASK,
            self.result_follow_on.retry_task)
        self.assertEqual(
            cert_res.ORDER_STATUS_REQUEST_PENDING.id,
            self.result_follow_on.status)
        self.assertEqual(
            cert_res.ORDER_STATUS_REQUEST_PENDING.message,
            self.result_follow_on.status_message)

    def _test_should_return_certificate_generated(self, method_to_test):
        self.result.status = cert_man.CertificateStatus.CERTIFICATE_GENERATED

        method_to_test(
            self.order, self.project, self.result_follow_on)

        self.assertEqual(
            common.RetryTasks.NO_ACTION_REQUIRED,
            self.result_follow_on.retry_task)
        self.assertEqual(
            cert_res.ORDER_STATUS_CERT_GENERATED.id,
            self.result_follow_on.status)
        self.assertEqual(
            cert_res.ORDER_STATUS_CERT_GENERATED.message,
            self.result_follow_on.status_message)

    def _test_should_raise_client_data_issue_seen(self, method_to_test):
        self.result.status = cert_man.CertificateStatus.CLIENT_DATA_ISSUE_SEEN

        self.assertRaises(
            cert_man.CertificateStatusClientDataIssue,
            method_to_test,
            self.order,
            self.project,
            self.result_follow_on
        )

    def _test_should_raise_status_not_supported(self, method_to_test):
        self.result.status = "Legend of Link"

        self.assertRaises(
            cert_man.CertificateStatusNotSupported,
            method_to_test,
            self.order,
            self.project,
            self.result_follow_on
        )

    def _config_cert_plugin(self):
        """Mock the certificate plugin manager."""
        cert_plugin_config = {
            'return_value.get_plugin.return_value': self.cert_plugin,
            'return_value.get_plugin_by_name.return_value': self.cert_plugin,
            'return_value.get_plugin_by_ca_id.return_value': self.cert_plugin
        }
        self.cert_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.CertificatePluginManager',
            **cert_plugin_config
        )
        self.cert_plugin_patcher.start()

    def _config_store_plugin(self):
        """Mock the secret store plugin manager."""
        store_plugin_config = {
            'return_value.get_plugin_retrieve_delete.return_value':
            self.store_plugin
        }
        self.store_plugin_patcher = mock.patch(
            'barbican.plugin.interface.secret_store'
            '.get_manager',
            **store_plugin_config
        )
        self.store_plugin_patcher.start()

    def _config_cert_event_plugin(self):
        """Mock the certificate event plugin manager."""
        self.cert_event_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '._EVENT_PLUGIN_MANAGER'
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

    def _config_save_barbican_meta_plugin(self):
        """Mock the save barbican plugin meta function."""
        self.save_barbican_barbican_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._save_barbican_metadata'
        )
        self.mock_barbican_save_plugin = (
            self.save_barbican_barbican_meta_patcher.start()
        )

    def _config_get_barbican_meta_plugin(self):
        """Mock the get barbican plugin meta function."""
        get_barbican_plugin_config = {'return_value': self.barbican_meta}
        self.get_barbican_plugin_meta_patcher = mock.patch(
            'barbican.tasks.certificate_resources._get_barbican_meta',
            **get_barbican_plugin_config
        )
        self.get_barbican_plugin_meta_patcher.start()

    def _config_barbican_meta_dto(self):
        """Mock the BarbicanMetaDTO."""
        get_plugin_config = {'return_value': self.barbican_meta_dto}
        self.barbican_meta_dto_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.BarbicanMetaDTO',
            **get_plugin_config
        )
        self.barbican_meta_dto_patcher.start()


class WhenIssuingCertificateRequests(BaseCertificateRequestsTestCase):
    """Tests the 'issue_certificate_request()' function."""

    def tearDown(self):
        super(WhenIssuingCertificateRequests, self).tearDown()

    def test_should_return_waiting_for_ca(self):
        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()

    def test_should_return_waiting_for_ca_as_retry(self):
        # For a retry, the plugin-name to look up would have already been
        # saved into the barbican metadata for the order, so just make sure
        # we can retrieve it.
        self.barbican_meta.update({'plugin_name': 'foo-plugin'})
        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()

    def test_should_return_certificate_generated(self):
        self._test_should_return_certificate_generated(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()

    def test_should_raise_client_data_issue_seen(self):
        self._test_should_raise_client_data_issue_seen(
            cert_res.issue_certificate_request)

    def _do_pyopenssl_stored_key_request(self):
        self.order_meta.update(self.stored_key_meta)

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        key_pem = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey)
        self.private_key_value = base64.b64encode(key_pem)
        self.public_key_value = "public_key"
        self.passphrase_value = None
        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect

        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

    def test_should_return_for_pyopenssl_stored_key(self):
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta.get('generated_csr'))

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_openssl_stored_key_ca_id_passed_in(self):
        self.stored_key_meta['ca_id'] = self.ca_id2
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

    def test_should_return_for_openssl_stored_key_pref_ca_defined(self):
        preferred_ca_repo.create_from(self.pref_ca)
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

    def test_should_return_for_openssl_stored_key_global_ca_defined(self):
        preferred_ca_repo.create_from(self.global_pref_ca)
        self._do_pyopenssl_stored_key_request()
        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

    def test_should_return_for_pyopenssl_stored_key_with_passphrase(self):
        self.order_meta.update(self.stored_key_meta)
        self.order_meta['container_ref'] = (
            "https://localhost/containers/" + self.container_with_passphrase.id
        )

        passphrase = "my secret passphrase"
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        key_pem = crypto.dump_privatekey(
            crypto.FILETYPE_PEM,
            pkey,
            passphrase=passphrase.encode('utf-8')
        )
        self.private_key_value = base64.b64encode(key_pem)
        self.public_key_value = "public_key"
        self.passphrase_value = base64.b64encode(passphrase.encode('utf-8'))
        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_pycrypto_stored_key_with_passphrase(self):
        self.order_meta.update(self.stored_key_meta)
        self.order_meta['container_ref'] = (
            "https://localhost/containers/" + self.container_with_passphrase.id
        )
        passphrase = "my secret passphrase"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.
            BestAvailableEncryption(encodeutils.safe_encode(passphrase))
        )
        self.private_key_value = base64.b64encode(private_key_pem)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.public_key_value = base64.b64encode(public_key_pem)

        self.passphrase_value = base64.b64encode(passphrase.encode('utf-8'))

        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_return_for_pycrypto_stored_key_without_passphrase(self):
        self.order_meta.update(self.stored_key_meta)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_value = base64.b64encode(private_key_pem)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.public_key_value = base64.b64encode(public_key_pem)

        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.

    def test_should_raise_for_pycrypto_stored_key_no_container(self):
        self.order_meta.update(self.stored_key_meta)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_value = base64.b64encode(private_key_pem)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.public_key_value = base64.b64encode(public_key_pem)

        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA
        container_repo.delete_project_entities(self.project.id)

        self.assertRaises(excep.StoredKeyContainerNotFound,
                          cert_res.issue_certificate_request,
                          self.order,
                          self.project,
                          self.result_follow_on)

    def test_should_raise_for_pycrypto_stored_key_no_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_value = base64.b64encode(private_key_pem)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.public_key_value = base64.b64encode(public_key_pem)

        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        secret_repo.delete_entity_by_id(
            self.private_key.id, self.external_project_id)

        # We need to commit deletions or we'll get deleted objects with deleted
        # set to True.  This is caused by SQLAlchemy's identity mapping and our
        # use of scoped_session.
        repositories.commit()
        self.order.meta.update(self.stored_key_meta)
        self.assertRaises(excep.StoredKeyPrivateKeyNotFound,
                          cert_res.issue_certificate_request,
                          self.order,
                          self.project,
                          self.result_follow_on)

    def test_should_return_for_pyopenssl_stored_key_with_extensions(self):
        self.order_meta.update(self.stored_key_meta)
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        self.private_key_value = base64.b64encode(crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey))

        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect
        self.order_meta['extensions'] = 'my ASN.1 extensions structure here'
        # TODO(alee-3) Add real extensions data here

        self.result.status = cert_man.CertificateStatus.WAITING_FOR_CA

        cert_res.issue_certificate_request(self.order,
                                           self.project,
                                           self.result_follow_on)

        self._verify_issue_certificate_plugins_called()
        self.assertIsNotNone(self.order.order_barbican_meta['generated_csr'])

        # TODO(alee-3) Add tests to validate the request based on the validator
        # code that dave-mccowan is adding.
        # TODO(alee-3) Add tests to validate the extensions in the request

    def test_should_raise_invalid_operation_seen(self):
        self.result.status = cert_man.CertificateStatus.INVALID_OPERATION

        self.assertRaises(
            cert_man.CertificateStatusInvalidOperation,
            cert_res.issue_certificate_request,
            self.order,
            self.project,
            self.result_follow_on
        )

    def test_should_return_ca_unavailable_for_request(self):
        retry_msec = 123
        status_msg = 'Test status'
        self.result.status = (
            cert_man.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)
        self.result.retry_msec = retry_msec
        self.result.status_message = status_msg
        order_ref = hrefs.convert_order_to_href(self.order.id)

        cert_res.issue_certificate_request(self.order,
                                           self.project,
                                           self.result_follow_on)

        self._verify_issue_certificate_plugins_called()

        epm = self.cert_event_plugin_patcher.target._EVENT_PLUGIN_MANAGER
        epm.notify_ca_is_unavailable.assert_called_once_with(
            self.project.id,
            order_ref,
            status_msg,
            retry_msec
        )
        self._verify_issue_certificate_plugins_called()
        self.assertEqual(
            common.RetryTasks.INVOKE_SAME_TASK,
            self.result_follow_on.retry_task)
        self.assertEqual(
            cert_res.ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE.id,
            self.result_follow_on.status)
        self.assertEqual(
            cert_res.ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE.message,
            self.result_follow_on.status_message)

    def test_should_raise_status_not_supported(self):
        self._test_should_raise_status_not_supported(
            cert_res.issue_certificate_request)

    def _verify_issue_certificate_plugins_called(self):
        self.cert_plugin.issue_certificate_request.assert_called_once_with(
            self.order.id,
            self.order_meta,
            self.plugin_meta,
            self.barbican_meta_dto
        )

        self.mock_save_plugin.assert_called_once_with(
            self.order,
            self.plugin_meta
        )

        self.mock_barbican_save_plugin.assert_called_once_with(
            self.order,
            self.barbican_meta
        )


class WhenCheckingCertificateRequests(BaseCertificateRequestsTestCase):
    """Tests the 'check_certificate_request()' function."""

    def setUp(self):
        super(WhenCheckingCertificateRequests, self).setUp()

    def tearDown(self):
        super(WhenCheckingCertificateRequests, self).tearDown()

    def test_should_return_waiting_for_ca(self):
        self._test_should_return_waiting_for_ca(
            cert_res.check_certificate_request)

        self._verify_check_certificate_plugins_called()

    def test_should_return_certificate_generated(self):
        self._test_should_return_certificate_generated(
            cert_res.check_certificate_request)

        self._verify_check_certificate_plugins_called()

    def test_should_raise_client_data_issue_seen(self):
        self._test_should_raise_client_data_issue_seen(
            cert_res.check_certificate_request)

    def test_should_raise_status_not_supported(self):
        self._test_should_raise_status_not_supported(
            cert_res.check_certificate_request)

    def test_should_return_ca_unavailable_for_request(self):
        retry_msec = 123
        status_msg = 'Test status'
        self.result.status = (
            cert_man.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)
        self.result.retry_msec = retry_msec
        self.result.status_message = status_msg
        order_ref = hrefs.convert_order_to_href(self.order.id)

        cert_res.check_certificate_request(self.order,
                                           self.project,
                                           self.result_follow_on)

        self._verify_check_certificate_plugins_called()

        epm = self.cert_event_plugin_patcher.target._EVENT_PLUGIN_MANAGER
        epm.notify_ca_is_unavailable.assert_called_once_with(
            self.project.id,
            order_ref,
            status_msg,
            retry_msec
        )
        self.assertEqual(
            common.RetryTasks.INVOKE_SAME_TASK,
            self.result_follow_on.retry_task)
        self.assertEqual(
            cert_res.ORDER_STATUS_CA_UNAVAIL_FOR_CHECK.id,
            self.result_follow_on.status)
        self.assertEqual(
            cert_res.ORDER_STATUS_CA_UNAVAIL_FOR_CHECK.message,
            self.result_follow_on.status_message)

    def _do_pyopenssl_stored_key_request(self):
        self.order_meta.update(self.stored_key_meta)

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        key_pem = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey)
        self.private_key_value = base64.b64encode(key_pem)
        self.public_key_value = "public_key"
        self.passphrase_value = None
        self.store_plugin.get_secret.side_effect = self.stored_key_side_effect

        self._test_should_return_waiting_for_ca(
            cert_res.issue_certificate_request)

        self._test_should_return_certificate_generated(
            cert_res.check_certificate_request)

    def test_should_return_for_pyopenssl_stored_key(self):
        self._do_pyopenssl_stored_key_request()
        self._verify_check_certificate_plugins_called()
        self.assertIsNotNone(
            self.order.order_barbican_meta.get('generated_csr'))

    def _verify_check_certificate_plugins_called(self):
        self.cert_plugin.check_certificate_status.assert_called_once_with(
            self.order.id,
            self.order_meta,
            self.plugin_meta,
            self.barbican_meta_dto
        )

        self.mock_save_plugin.assert_called_with(
            self.order,
            self.plugin_meta
        )


class WhenCreatingSubordinateCAs(database_utils.RepositoryTestCase):
    """Tests the 'create_subordinate_ca()' function."""

    def setUp(self):
        super(WhenCreatingSubordinateCAs, self).setUp()
        self.project = res.get_or_create_project('12345')
        self.project2 = res.get_or_create_project('56789')

        self.subject_name = "cn=subca1 signing certificate, o=example.com"
        self.creator_id = "user12345"
        self.name = "Subordinate CA #1"
        self.description = "This is a test subordinate CA"
        self.plugin_name = "dogtag_plugin"

        # create parent ca
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        parsed_ca = {'plugin_name': self.plugin_name,
                     'plugin_ca_id': 'ca_master',
                     'expiration': expiration.isoformat(),
                     'name': 'Dogtag CA',
                     'description': 'Master CA for Dogtag plugin',
                     'ca_signing_certificate': 'XXXXX',
                     'intermediates': 'YYYYY'}

        self.parent_ca = models.CertificateAuthority(parsed_ca)
        ca_repo.create_from(self.parent_ca)
        self.parent_ca_ref = 'https://localhost:6311/cas/' + self.parent_ca.id

        self.new_ca_dict = {
            'plugin_ca_id': 'ca_subordinate',
            'expiration': expiration.isoformat(),
            'name': 'Dogtag Subordinate CA',
            'description': 'Subordinate CA for Dogtag plugin',
            'ca_signing_certificate': 'XXXXX',
            'intermediates': 'YYYYY',
        }

        # mock plugin and calls to plugin
        self.cert_plugin = mock.MagicMock()
        self.cert_plugin.supports_create_ca.return_value = True
        self.cert_plugin.create_ca.return_value = self.new_ca_dict
        self._config_cert_plugin()

    def tearDown(self):
        super(WhenCreatingSubordinateCAs, self).tearDown()
        self.cert_plugin_patcher.stop()

    def test_should_create_subordinate_ca(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        self.assertIsInstance(subca, models.CertificateAuthority)
        self.assertEqual(self.project.id, subca.project_id)
        self.assertEqual(self.creator_id, subca.creator_id)
        self.assertEqual(self.plugin_name, subca.plugin_name)

    def test_should_raise_invalid_parent_ca(self):
        self.parent_ca_ref = 'https://localhost:6311/cas/' + "BAD-CA-REF"
        self.assertRaises(
            excep.InvalidParentCA,
            cert_res.create_subordinate_ca,
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )

    def test_should_raise_unauthorized_parent_ca(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project2,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        subca_ref = hrefs.convert_certificate_authority_to_href(subca.id)
        self.assertRaises(
            excep.UnauthorizedSubCA,
            cert_res.create_subordinate_ca,
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=subca_ref,
            creator_id=self.creator_id)

    def test_should_raise_subcas_not_supported(self):
        self.cert_plugin.supports_create_ca.return_value = False
        self.assertRaises(
            excep.SubCAsNotSupported,
            cert_res.create_subordinate_ca,
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )

    def test_should_raise_subcas_not_created(self):
        self.cert_plugin.create_ca.return_value = None
        self.assertRaises(
            excep.SubCANotCreated,
            cert_res.create_subordinate_ca,
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )

    def test_should_delete_subca(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        self.assertIsInstance(subca, models.CertificateAuthority)
        cert_res.delete_subordinate_ca(self.project.external_id, subca)
        self.cert_plugin.delete_ca.assert_called_once_with(subca.plugin_ca_id)

    def test_should_delete_subca_and_all_related_db_entities(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        project_ca = models.ProjectCertificateAuthority(
            self.project.id,
            subca.id
        )
        project_ca_repo.create_from(project_ca)
        preferred_ca = models.PreferredCertificateAuthority(
            self.project.id,
            subca.id)
        preferred_ca_repo.create_from(preferred_ca)
        cert_res.delete_subordinate_ca(self.project.external_id, subca)
        self.cert_plugin.delete_ca.assert_called_once_with(subca.plugin_ca_id)

    def test_should_raise_when_delete_pref_subca_with_other_project_ca(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        project_ca = models.ProjectCertificateAuthority(
            self.project.id,
            subca.id
        )
        project_ca_repo.create_from(project_ca)
        preferred_ca = models.PreferredCertificateAuthority(
            self.project.id,
            subca.id)
        preferred_ca_repo.create_from(preferred_ca)
        subca2 = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        project_ca2 = models.ProjectCertificateAuthority(
            self.project.id,
            subca2.id
        )
        project_ca_repo.create_from(project_ca2)
        self.assertRaises(
            excep.CannotDeletePreferredCA,
            cert_res.delete_subordinate_ca,
            self.project.external_id,
            subca
        )

    def test_should_raise_cannot_delete_base_ca(self):
        self.assertRaises(
            excep.CannotDeleteBaseCA,
            cert_res.delete_subordinate_ca,
            self.project.external_id,
            self.parent_ca
        )

    def test_should_raise_unauthorized_subca_delete(self):
        subca = cert_res.create_subordinate_ca(
            project_model=self.project,
            name=self.name,
            description=self.description,
            subject_dn=self.subject_name,
            parent_ca_ref=self.parent_ca_ref,
            creator_id=self.creator_id
        )
        self.assertRaises(
            excep.UnauthorizedSubCA,
            cert_res.delete_subordinate_ca,
            self.project2.external_id,
            subca
        )

    def _config_cert_plugin(self):
        """Mock the certificate plugin manager."""
        cert_plugin_config = {
            'return_value.get_plugin.return_value': self.cert_plugin,
            'return_value.get_plugin_by_name.return_value': self.cert_plugin,
            'return_value.get_plugin_by_ca_id.return_value': self.cert_plugin
        }
        self.cert_plugin_patcher = mock.patch(
            'barbican.plugin.interface.certificate_manager'
            '.CertificatePluginManager',
            **cert_plugin_config
        )
        self.cert_plugin_patcher.start()
