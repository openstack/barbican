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

import os
import tempfile

import mock
from requests import exceptions as request_exceptions
import testtools

try:
    import barbican.plugin.dogtag as dogtag_import
    import barbican.plugin.interface.certificate_manager as cm
    import barbican.plugin.interface.secret_store as sstore

    import pki
    import pki.cert as dogtag_cert
    imports_ok = True
except ImportError:
    # dogtag imports probably not available
    imports_ok = False


@testtools.skipIf(not imports_ok, "Dogtag imports not available")
class WhenTestingDogtagKRAPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingDogtagKRAPlugin, self).setUp()
        self.keyclient_mock = mock.MagicMock(name="KeyClient mock")
        self.patcher = mock.patch('pki.crypto.NSSCryptoProvider')
        self.patcher.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.dogtag_plugin = mock.MagicMock(
            nss_db_path=self.nss_dir)
        self.plugin = dogtag_import.DogtagKRAPlugin(self.cfg_mock)
        self.plugin.keyclient = self.keyclient_mock

    def tearDown(self):
        super(WhenTestingDogtagKRAPlugin, self).tearDown()
        self.patcher.stop()
        os.rmdir(self.nss_dir)

    def test_generate(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 128)
        context = mock.MagicMock()
        self.plugin.generate_symmetric_key(key_spec, context)

        self.keyclient_mock.generate_symmetric_key.assert_called_once_with(
            mock.ANY,
            sstore.KeyAlgorithm.AES.upper(),
            128,
            mock.ANY)

    def test_generate_non_supported_algorithm(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.EC, 192)
        context = mock.MagicMock()
        self.assertRaises(
            dogtag_import.DogtagPluginAlgorithmException,
            self.plugin.generate_symmetric_key,
            key_spec,
            context
        )

    def test_raises_error_with_no_pem_path(self):
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(pem_path=None, nss_db_path='/tmp')
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagKRAPlugin,
            m,
        )

    def test_raises_error_with_no_nss_password(self):
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(nss_password=None)
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagKRAPlugin,
            m,
        )

    def test_store_secret(self):
        payload = 'encrypt me!!'
        key_spec = mock.MagicMock()
        content_type = mock.MagicMock()
        context = mock.MagicMock()
        transport_key = None
        secret_dto = sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                      payload,
                                      key_spec,
                                      content_type,
                                      transport_key)
        self.plugin.store_secret(secret_dto, context)
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
        context = mock.MagicMock()
        transport_key = mock.MagicMock()
        secret_dto = sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                      payload,
                                      key_spec,
                                      content_type,
                                      transport_key)
        self.plugin.store_secret(secret_dto, context)
        self.keyclient_mock.archive_pki_options.assert_called_once_with(
            mock.ANY,
            "passPhrase",
            payload,
            key_algorithm=None,
            key_size=None)

    def test_get_secret(self):
        key_spec = mock.MagicMock()
        context = mock.MagicMock()
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.SECRET_TYPE:
            sstore.SecretType.SYMMETRIC,
            dogtag_import.DogtagKRAPlugin.SECRET_KEYSPEC: key_spec,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1'
        }
        self.plugin.get_secret(secret_metadata, context)

        self.keyclient_mock.retrieve_key.assert_called_once_with('key1', None)

    def test_get_secret_with_twsk(self):
        key_spec = mock.MagicMock()
        context = mock.MagicMock()
        twsk = mock.MagicMock()
        secret_metadata = {
            dogtag_import.DogtagKRAPlugin.SECRET_TYPE:
            sstore.SecretType.SYMMETRIC,
            dogtag_import.DogtagKRAPlugin.SECRET_KEYSPEC: key_spec,
            dogtag_import.DogtagKRAPlugin.KEY_ID: 'key1',
            'trans_wrapped_session_key': twsk
        }
        self.plugin.get_secret(secret_metadata, context)

        self.keyclient_mock.retrieve_key.assert_called_once_with('key1', twsk)

    def test_supports_symmetric_aes_key_generation(self):
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 256)
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
class WhenTestingDogtagCAPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingDogtagCAPlugin, self).setUp()
        self.certclient_mock = mock.MagicMock(name="CertClient mock")
        self.patcher = mock.patch('pki.crypto.NSSCryptoProvider')
        self.patcher.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.dogtag_plugin = mock.MagicMock(
            nss_db_path=self.nss_dir)
        self.plugin = dogtag_import.DogtagCAPlugin(self.cfg_mock)
        self.plugin.certclient = self.certclient_mock
        self.order_id = mock.MagicMock()
        self.profile_id = mock.MagicMock()

        # request generated
        self.request = mock.MagicMock()
        self.request_id_mock = mock.MagicMock()
        self.request.request_id = self.request_id_mock
        self.request.request_status = dogtag_cert.CertRequestStatus.COMPLETE
        self.cert_id_mock = mock.MagicMock()
        self.request.cert_id = self.cert_id_mock

        # cert generated
        self.cert = mock.MagicMock()
        self.cert_encoded_mock = mock.MagicMock()
        self.cert.encoded = self.cert_encoded_mock
        self.cert_pkcs7_mock = mock.MagicMock()
        self.cert.pkcs7_cert_chain = self.cert_pkcs7_mock

        # for cancel/modify
        self.review_response = mock.MagicMock()

        # modified request
        self.modified_request = mock.MagicMock()
        self.modified_request_id_mock = mock.MagicMock()
        self.modified_request.request_id = self.modified_request_id_mock
        self.modified_request.request_status = (
            dogtag_cert.CertRequestStatus.COMPLETE)
        self.modified_request.cert_id = self.cert_id_mock

    def tearDown(self):
        super(WhenTestingDogtagCAPlugin, self).tearDown()
        self.patcher.stop()
        os.rmdir(self.nss_dir)

    def test_issue_certificate_request(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, self.cert)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CERTIFICATE_GENERATED,
                         "result_dto status incorrect")

        self.assertEqual(result_dto.certificate,
                         self.cert_encoded_mock)

        self.assertEqual(result_dto.intermediates,
                         self.cert_pkcs7_mock)

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_return_data_error_with_no_profile_id(self):
        order_meta = {}
        plugin_meta = {}

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto status incorrect")

        self.assertEqual(result_dto.status_message,
                         "No profile_id specified")

    def test_issue_return_data_error_with_request_rejected(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}
        self.request.request_status = dogtag_cert.CertRequestStatus.REJECTED

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto status incorrect")

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_return_canceled_with_request_canceled(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}
        self.request.request_status = dogtag_cert.CertRequestStatus.CANCELED

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.REQUEST_CANCELED,
                         "result_dto status incorrect")

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_return_waiting_with_request_pending(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}
        self.request.request_status = dogtag_cert.CertRequestStatus.PENDING

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.request, None)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.WAITING_FOR_CA,
                         "result_dto status incorrect")

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_raises_error_request_complete_no_cert(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
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
            plugin_meta
        )

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_raises_error_request_unknown_status(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
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
            plugin_meta
        )

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.request_id_mock
        )

    def test_issue_return_client_error_bad_request_exception(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            pki.BadRequestException("bad request"))

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto status incorrect")

    def test_issue_raises_error_pki_exception(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            pki.PKIException("generic enrollment error"))

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta
        )

    def test_issue_return_ca_unavailable(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID: self.profile_id}
        plugin_meta = {}

        self.certclient_mock.enroll_cert.side_effect = (
            request_exceptions.RequestException())

        result_dto = self.plugin.issue_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         "result_dto status incorrect")

    def test_cancel_request(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.cancel_request.return_value = None
        self.certclient_mock.review_request.return_value = self.review_response

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.REQUEST_CANCELED,
                         "result_dto_status incorrect")

    def test_cancel_no_request_found(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            pki.RequestNotFoundException("request_not_found"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.review_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto_status incorrect")

    def test_cancel_conflicting_operation(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.return_value = self.review_response
        self.certclient_mock.cancel_request.side_effect = (
            pki.ConflictingOperationException("conflicting_operation"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.INVALID_OPERATION,
                         "result_dto_status incorrect")

    def test_cancel_ca_unavailable(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            request_exceptions.RequestException("request_exception"))

        result_dto = self.plugin.cancel_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         "result_dto_status incorrect")

    def test_cancel_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.cancel_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta
        )

    def test_check_status(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.get_request.return_value = self.request
        self.certclient_mock.get_cert.return_value = self.cert

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.certclient_mock.get_cert.assert_called_once_with(
            self.cert_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CERTIFICATE_GENERATED,
                         "result_dto_status incorrect")

        self.assertEqual(result_dto.certificate,
                         self.cert_encoded_mock)

    def test_check_status_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.check_certificate_status,
            self.order_id,
            order_meta,
            plugin_meta
        )

    def test_check_status_rejected(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.REJECTED
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto_status incorrect")

        self.assertEqual(result_dto.certificate,
                         None)

    def test_check_status_canceled(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.CANCELED
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.REQUEST_CANCELED,
                         "result_dto_status incorrect")

        self.assertEqual(result_dto.certificate,
                         None)

    def test_check_status_pending(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.request.request_status = dogtag_cert.CertRequestStatus.PENDING
        self.certclient_mock.get_request.return_value = self.request

        result_dto = self.plugin.check_certificate_status(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.get_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.WAITING_FOR_CA,
                         "result_dto_status incorrect")

        self.assertEqual(result_dto.certificate,
                         None)

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
            plugin_meta
        )

    def test_modify_request(self):
        order_meta = {dogtag_import.DogtagCAPlugin.PROFILE_ID:
                      self.profile_id}
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.cancel_request.return_value = None
        self.certclient_mock.review_request.return_value = self.review_response

        enrollment_result = dogtag_cert.CertEnrollmentResult(
            self.modified_request, self.cert)
        enrollment_results = [enrollment_result]
        self.certclient_mock.enroll_cert.return_value = enrollment_results

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.certclient_mock.enroll_cert.assert_called_once_with(
            self.profile_id,
            order_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CERTIFICATE_GENERATED,
                         "result_dto_status incorrect")

        self.assertEqual(result_dto.certificate,
                         self.cert_encoded_mock)

        self.assertEqual(result_dto.intermediates,
                         self.cert_pkcs7_mock)

        self.assertEqual(
            plugin_meta.get(dogtag_import.DogtagCAPlugin.REQUEST_ID),
            self.modified_request_id_mock
        )

    def test_modify_no_request_found(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            pki.RequestNotFoundException("request_not_found"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.review_request.assert_called_once_with(
            self.request_id_mock)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                         "result_dto_status incorrect")

    def test_modify_conflicting_operation(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.return_value = self.review_response
        self.certclient_mock.cancel_request.side_effect = (
            pki.ConflictingOperationException("conflicting_operation"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.certclient_mock.cancel_request.assert_called_once_with(
            self.request_id_mock,
            self.review_response)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.INVALID_OPERATION,
                         "result_dto_status incorrect")

    def test_modify_ca_unavailable(self):
        order_meta = mock.ANY
        plugin_meta = {dogtag_import.DogtagCAPlugin.REQUEST_ID:
                       self.request_id_mock}
        self.certclient_mock.review_request.side_effect = (
            request_exceptions.RequestException("request_exception"))

        result_dto = self.plugin.modify_certificate_request(
            self.order_id, order_meta, plugin_meta)

        self.assertEqual(result_dto.status,
                         cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST,
                         "result_dto_status incorrect")

    def test_modify_raise_error_no_request_id(self):
        order_meta = mock.ANY
        plugin_meta = {}

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.modify_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta
        )
