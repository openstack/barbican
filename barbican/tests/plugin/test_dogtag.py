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
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import testtools

from barbican.tests import utils

try:
    import barbican.plugin.dogtag as dogtag_import
    import barbican.plugin.interface.secret_store as sstore

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
