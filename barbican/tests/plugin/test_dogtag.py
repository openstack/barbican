# Copyright (c) 2014 Red Hat, Inc.
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
import os
import tempfile
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from requests import exceptions as request_exceptions
import testtools

from barbican.tests import keys
from barbican.tests import utils

try:
    import barbican.plugin.dogtag as dogtag_import
    import barbican.plugin.interface.certificate_manager as cm
    import barbican.plugin.interface.secret_store as sstore

    import pki
    import pki.cert as dogtag_cert
    import pki.key as dogtag_key
    imports_ok = True
except ImportError:
    # dogtag imports probably not available
    imports_ok = False


@testtools.skipIf(not imports_ok, "Dogtag imports not available")
class WhenTestingDogtagKRAPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingDogtagKRAPlugin, self).setUp()
        self.keyclient_mock = mock.MagicMock(name="KeyClient mock")
        self.patcher = mock.patch('pki.crypto.NSSCryptoProvider')
        self.patcher.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        self.plugin_name = "Test Dogtag KRA plugin"
        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.dogtag_plugin = mock.MagicMock(
            nss_db_path=self.nss_dir,
            plugin_name=self.plugin_name,
            retries=3)
        self.plugin = dogtag_import.DogtagKRAPlugin(self.cfg_mock)
        self.plugin.keyclient = self.keyclient_mock

    def tearDown(self):
        super(WhenTestingDogtagKRAPlugin, self).tearDown()
        self.patcher.stop()
        os.rmdir(self.nss_dir)

    def test_get_plugin_name(self):
        self.assertEqual(self.plugin_name, self.plugin.get_plugin_name())

    def test_generate_symmetric_key(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 128)
        self.plugin.generate_symmetric_key(key_spec)

        self.keyclient_mock.generate_symmetric_key.assert_called_once_with(
            mock.ANY,
            sstore.KeyAlgorithm.AES.upper(),
            128,
            mock.ANY)

    def test_generate_asymmetric_key(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.RSA, 2048)
        self.plugin.generate_asymmetric_key(key_spec)

        self.keyclient_mock.generate_asymmetric_key.assert_called_once_with(
            mock.ANY,
            sstore.KeyAlgorithm.RSA.upper(),
            2048,
            mock.ANY)

    def test_generate_non_supported_algorithm(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.EC, 192)
        self.assertRaises(
            dogtag_import.DogtagPluginAlgorithmException,
            self.plugin.generate_symmetric_key,
            key_spec
        )

    def test_raises_error_with_no_pem_path(self):
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(pem_path=None, nss_db_path='/tmp')
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagKRAPlugin,
            m,
        )

    def test_store_secret(self):
        payload = 'encrypt me!!'
        key_spec = mock.MagicMock()
        content_type = mock.MagicMock()
        transport_key = None
        secret_dto = sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                      payload,
                                      key_spec,
                                      content_type,
                                      transport_key)
        self.plugin.store_secret(secret_dto)
        self.keyclient_mock.archive_key.assert_called_once_with(
            mock.ANY,
            "passPhrase",
            payload,
            key_algorithm=None,
            key_size=None)

    def test_store_secret_with_tkey_id(self):
        payload = 'data wrapped in PKIArchiveOptions object'
        key_spec = mock.MagicMock()
        content_type = mock.MagicMock()
        transport_key = mock.MagicMock()
        secret_dto = sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                      payload,
                                      key_spec,
                                      content_type,
                                      transport_key)
        self.plugin.store_secret(secret_dto)
        self.keyclient_mock.archive_pki_options.assert_called_once_with(
            mock.ANY,
            "passPhrase",
            payload,
            key_algorithm=None,
            key_size=None)

    def test_get_secret(self):
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.ALG: sstore.KeyAlgorithm.AES,
            dogtag_import.DogtagKRAPlugin.BIT_LENGTH: 256,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1'
        }
        self.plugin.get_secret(sstore.SecretType.SYMMETRIC, secret_metadata)

        self.keyclient_mock.retrieve_key.assert_called_once_with('key1', None)

    def test_get_secret_with_twsk(self):
        twsk = mock.MagicMock()
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.ALG: sstore.KeyAlgorithm.AES,
            dogtag_import.DogtagKRAPlugin.BIT_LENGTH: 256,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1',
            'trans_wrapped_session_key': twsk
        }
        self.plugin.get_secret(sstore.SecretType.SYMMETRIC, secret_metadata)

        self.keyclient_mock.retrieve_key.assert_called_once_with('key1', twsk)

    def test_get_private_key(self):
        test_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        key_data = dogtag_key.KeyData()
        key_data.data = test_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        self.keyclient_mock.retrieve_key.return_value = key_data
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.ALG: sstore.KeyAlgorithm.RSA,
            dogtag_import.DogtagKRAPlugin.BIT_LENGTH: 2048,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1',
            dogtag_import.DogtagKRAPlugin.CONVERT_TO_PEM: 'true'
        }
        result = self.plugin.get_secret(sstore.SecretType.PRIVATE,
                                        secret_metadata)

        self.assertEqual(
            test_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()),
            result.secret
        )

    def test_get_public_key(self):
        test_public_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()).public_key()
        key_info = dogtag_key.KeyInfo()
        key_info.public_key = test_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1)
        self.keyclient_mock.get_key_info.return_value = key_info
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.ALG: sstore.KeyAlgorithm.RSA,
            dogtag_import.DogtagKRAPlugin.BIT_LENGTH: 2048,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1',
            dogtag_import.DogtagKRAPlugin.CONVERT_TO_PEM: 'true'
        }
        result = self.plugin.get_secret(sstore.SecretType.PUBLIC,
                                        secret_metadata)

        self.assertEqual(
            test_public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.PKCS1),
            result.secret
        )

    def test_store_passphrase_for_using_in_private_key_retrieval(self):

        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.RSA, 2048,
                                  passphrase="password123")

        # Mock the response for passphrase archival
        request_response = dogtag_key.KeyRequestResponse()
        request_info = dogtag_key.KeyRequestInfo()
        request_info.key_url = "https://example_url/1"
        request_response.request_info = request_info
        self.keyclient_mock.archive_key.return_value = request_response

        asym_key_DTO = self.plugin.generate_asymmetric_key(key_spec)

        self.assertEqual(
            '1',
            asym_key_DTO.private_key_meta[
                dogtag_import.DogtagKRAPlugin.PASSPHRASE_KEY_ID]
        )

        self.keyclient_mock.generate_asymmetric_key.assert_called_once_with(
            mock.ANY,
            sstore.KeyAlgorithm.RSA.upper(),
            2048,
            mock.ANY)

    def test_supports_symmetric_aes_key_generation(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 256)
        self.assertTrue(
            self.plugin.generate_supports(key_spec)
        )

    def test_supports_asymmetric_rsa_key_generation(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.RSA, 2048)
        self.assertTrue(
            self.plugin.generate_supports(key_spec)
        )

    def test_supports_asymmetric_ec_key_generation(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.EC, 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )

    def test_supports_symmetric_dh_key_generation(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.DIFFIE_HELLMAN, 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )

    def test_does_not_support_unknown_type(self):
        key_spec = sstore.KeySpec("SOMETHING_RANDOM", 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )


@testtools.skipIf(not imports_ok, "Dogtag imports not available")
class WhenTestingDogtagCAPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingDogtagCAPlugin, self).setUp()
        self.certclient_mock = mock.MagicMock(name="CertClient mock")
        self.patcher = mock.patch('pki.crypto.NSSCryptoProvider')
        self.patcher2 = mock.patch('pki.client.PKIConnection')
        self.patcher.start()
        self.patcher2.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        # create expiration file for test
        fh, self.expiration_data_path = tempfile.mkstemp()
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(days=2)
        os.write(fh, exp_time.strftime(
            "%Y-%m-%d %H:%M:%S.%f"))
        os.close(fh)

        # create host CA file for test
        fh, self.host_ca_path = tempfile.mkstemp()
        os.write(fh, "host_ca_aid")
        os.close(fh)

        self.approved_profile_id = "caServerCert"
        CONF = dogtag_import.CONF
        CONF.dogtag_plugin.nss_db_path = self.nss_dir
        CONF.dogtag_plugin.ca_expiration_data_path = self.expiration_data_path
        CONF.dogtag_plugin.ca_host_aid_path = self.host_ca_path
        CONF.dogtag_plugin.auto_approved_profiles = [self.approved_profile_id]
        CONF.dogtag_plugin.dogtag_host = "localhost"
        CONF.dogtag_plugin.dogtag_port = 8443
        CONF.dogtag_plugin.simple_cmc_profile = "caOtherCert"
        self.cfg = CONF

        self.plugin = dogtag_import.DogtagCAPlugin(CONF)
        self.plugin.certclient = self.certclient_mock
        self.order_id = mock.MagicMock()
        self.profile_id = mock.MagicMock()

        # request generated
        self.request_id_mock = mock.MagicMock()
        self.request = dogtag_cert.CertRequestInfo()
        self.request.request_id = self.request_id_mock
        self.request.request_status = dogtag_cert.CertRequestStatus.COMPLETE
        self.cert_id_mock = mock.MagicMock()
        self.request.cert_id = self.cert_id_mock

        # cert generated
        self.cert = mock.MagicMock()
        self.cert.encoded = keys.get_certificate_pem()
        self.cert.pkcs7_cert_chain = keys.get_certificate_der()

        # for cancel/modify
        self.review_response = mock.MagicMock()

        # modified request
        self.modified_request = mock.MagicMock()
        self.modified_request_id_mock = mock.MagicMock()
        self.modified_request.request_id = self.modified_request_id_mock
        self.modified_request.request_status = (
            dogtag_cert.CertRequestStatus.COMPLETE)
        self.modified_request.cert_id = self.cert_id_mock

        self.barbican_meta_dto = cm.BarbicanMetaDTO()

    def tearDown(self):
        super(WhenTestingDogtagCAPlugin, self).tearDown()
        self.patcher2.stop()
        self.patcher.stop()
        os.rmdir(self.nss_dir)
        os.remove(self.host_ca_path)
        os.remove(self.expiration_data_path)

    def _process_approved_profile_request(self, order_meta, plugin_meta):
        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, self.cert)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.approved_profile_id,
            order_meta)

        self.assertEqual(cm.CertificateStatus.CERTIFICATE_GENERATED,
                         result_dto.status,
                         "result_dto status incorrect")

        self.assertEqual(base64.b64encode(keys.get_certificate_pem()),
                         result_dto.certificate)

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID)
        )

    def _process_non_approved_profile_request(self, order_meta, plugin_meta,
                                              profile_id, inputs=None):
        if inputs is None:
            inputs = {
                'cert_request_type': 'pkcs10',
                'cert_request': base64.b64decode(
                    order_meta.get('request_data'))
            }

        # mock CertRequestInfo
        enrollment_result = dogtag_cert.CertRequestInfo()
        enrollment_result.request_id = self.request_id_mock
        enrollment_result.request_status = (
            dogtag_cert.CertRequestStatus.PENDING)

        # mock CertRequestInfoCollection
        enrollment_results = dogtag_cert.CertRequestInfoCollection()
        enrollment_results.cert_request_info_list = (
            [enrollment_result])

        self.certclient_mock.create_enrollment_request.return_value = (
            enrollment_result)
        self.certclient_mock.submit_enrollment_request.return_value = (
            enrollment_results)

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.create_enrollment_request.assert_called_once_with(
            profile_id, inputs)

        self.certclient_mock.submit_enrollment_request.assert_called_once_with(
            enrollment_result)

        self.assertEqual(cm.CertificateStatus.WAITING_FOR_CA,
                         result_dto.status,
                         "result_dto status incorrect")

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID)
        )

    def test_issue_simple_cmc_request(self):
        order_meta = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.SIMPLE_CMC_REQUEST,
            'request_data': base64.b64encode(keys.get_csr_pem())
        }
        plugin_meta = {}
        self._process_non_approved_profile_request(
            order_meta,
            plugin_meta,
            self.cfg.dogtag_plugin.simple_cmc_profile)

    def test_issue_full_cmc_request(self):
        order_meta = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.FULL_CMC_REQUEST,
            'request_data': 'Full CMC data ...'
        }
        plugin_meta = {}

        self.assertRaises(
            dogtag_import.DogtagPluginNotSupportedException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_issue_stored_key_request(self):
        order_meta = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.STORED_KEY_REQUEST,
            'request_data': base64.b64encode(keys.get_csr_pem())
        }
        plugin_meta = {}
        self._process_non_approved_profile_request(
            order_meta,
            plugin_meta,
            self.cfg.dogtag_plugin.simple_cmc_profile)

    def test_issue_custom_key_request(self):
        order_meta = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.CUSTOM_REQUEST,
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id,
        }
        plugin_meta = {}
        self._process_approved_profile_request(order_meta, plugin_meta)

    def test_issue_no_cert_request_type_provided(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}
        self._process_approved_profile_request(order_meta, plugin_meta)

    def test_issue_bad_cert_request_type_provided(self):
        order_meta = {
            cm.REQUEST_TYPE: 'BAD_REQUEST_TYPE',
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id,
        }
        plugin_meta = {}

        self.assertRaises(
            dogtag_import.DogtagPluginNotSupportedException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_issue_return_data_error_with_no_profile_id(self):
        order_meta = {}
        plugin_meta = {}

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto status incorrect")

        self.assertEqual(result_dto.status_message,
                         "No profile_id specified")

    def test_issue_return_data_error_with_request_rejected(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}
        self.request.request_status = dogtag_cert.CertRequestStatus.REJECTED

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.approved_profile_id,
            order_meta)

        self.assertEqual(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         result_dto.status,
                         "result_dto status incorrect")

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID))

    def test_issue_return_canceled_with_request_canceled(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}
        self.request.request_status = dogtag_cert.CertRequestStatus.CANCELED

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.approved_profile_id,
            order_meta)

        self.assertEqual(cm.CertificateStatus.REQUEST_CANCELED,
                         result_dto.status,
                         "result_dto status incorrect")

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
        )

    def test_issue_return_waiting_with_request_pending(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: "otherProfile",
            'cert_request': base64.b64encode(keys.get_csr_pem())}
        plugin_meta = {}
        inputs = {
            'cert_request': keys.get_csr_pem(),
            dogtag_import.DogtagCAPlugin.PROFILE_ID: "otherProfile"
        }
        self._process_non_approved_profile_request(
            order_meta, plugin_meta, "otherProfile", inputs)

    def test_issue_raises_error_request_complete_no_cert(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID)
        )

    def test_issue_raises_error_request_unknown_status(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}

        self.request.request_status = "unknown_status"
        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

        self.assertEqual(
            self.request_id_mock,
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID)
        )

    def test_issue_return_client_error_bad_request_exception(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            pki.BadRequestException("bad request"))

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.approved_profile_id,
            order_meta)

        self.assertEqual(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         result_dto.status,
                         "result_dto status incorrect")

    def test_issue_raises_error_pki_exception(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            pki.PKIException("generic enrollment error"))

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_issue_return_ca_unavailable(self):
        order_meta = {
            dogtag_import.DogtagCAPlugin.PROFILE_ID: self.approved_profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            request_exceptions.RequestException())

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.approved_profile_id,
            order_meta)

        self.assertEqual(cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         result_dto.status,
                         "result_dto status incorrect")

    def test_cancel_request(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.cancel_request.return_value = None
        self.certclient_mock.review_request.return_value = self.review_response

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(cm.CertificateStatus.REQUEST_CANCELED,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_cancel_no_request_found(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            pki.RequestNotFoundException("request_not_found"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.review_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_cancel_conflicting_operation(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.return_value = self.review_response
        self.certclient_mock.cancel_request.side_effect = (
            pki.ConflictingOperationException("conflicting_operation"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(cm.CertificateStatus.INVALID_OPERATION,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_cancel_ca_unavailable(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            request_exceptions.RequestException("request_exception"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.assertEqual(cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_cancel_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.cancel_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_check_status(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.get_request.return_value = self.request
        self.certclient_mock.get_cert.return_value = self.cert

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.certclient_mock.get_cert.assert_called_once_with(
            self.cert_id_mock)

        self.assertEqual(cm.CertificateStatus.CERTIFICATE_GENERATED,
                         result_dto.status,
                         "result_dto_status incorrect")

        self.assertEqual(keys.get_certificate_pem(),
                         result_dto.certificate)

    def test_check_status_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.check_certificate_status,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_check_status_rejected(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.REJECTED
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         result_dto.status,
                         "result_dto_status incorrect")

        self.assertIsNone(result_dto.certificate)

    def test_check_status_canceled(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.CANCELED
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(cm.CertificateStatus.REQUEST_CANCELED,
                         result_dto.status,
                         "result_dto_status incorrect")

        self.assertIsNone(result_dto.certificate)

    def test_check_status_pending(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.PENDING
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(cm.CertificateStatus.WAITING_FOR_CA,
                         result_dto.status,
                         "result_dto_status incorrect")

        self.assertIsNone(result_dto.certificate)

    def test_check_status_raises_error_complete_no_cert(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.get_request.return_value = self.request
        self.certclient_mock.get_cert.return_value = None

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.check_certificate_status,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )

    def test_modify_request(self):
        order_meta = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.SIMPLE_CMC_REQUEST,
            'request_data': base64.b64encode(keys.get_csr_pem())
        }
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self._process_non_approved_profile_request(
            order_meta,
            plugin_meta,
            self.cfg.dogtag_plugin.simple_cmc_profile)

        self.certclient_mock.cancel_request.return_value = None
        self.certclient_mock.review_request.return_value = self.review_response

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(cm.CertificateStatus.WAITING_FOR_CA,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_modify_no_request_found(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            pki.RequestNotFoundException("request_not_found"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.review_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_modify_conflicting_operation(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.return_value = self.review_response
        self.certclient_mock.cancel_request.side_effect = (
            pki.ConflictingOperationException("conflicting_operation"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(cm.CertificateStatus.INVALID_OPERATION,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_modify_ca_unavailable(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            request_exceptions.RequestException("request_exception"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta, self.barbican_meta_dto)

        self.assertEqual(cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         result_dto.status,
                         "result_dto_status incorrect")

    def test_modify_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.modify_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto
        )
