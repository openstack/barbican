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

import mock
import os
import tempfile
import testtools

try:
    from barbican.crypto import plugin as plugin_import
    from barbican.crypto.dogtag_crypto import DogtagCryptoPlugin
    from barbican.crypto.dogtag_crypto import DogtagPluginAlgorithmException
    from barbican.model import models
    imports_ok = True
except:
    # dogtag imports probably not available
    imports_ok = False


class WhenTestingDogtagCryptoPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingDogtagCryptoPlugin, self).setUp()
        if not imports_ok:
            return

        self.keyclient_mock = mock.MagicMock(name="KeyClient mock")
        self.patcher = mock.patch('pki.cryptoutil.NSSCryptoUtil')
        self.patcher.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.dogtag_crypto_plugin = mock.MagicMock(
            nss_db_path=self.nss_dir)
        self.plugin = DogtagCryptoPlugin(self.cfg_mock)
        self.plugin.keyclient = self.keyclient_mock

    def tearDown(self):
        super(WhenTestingDogtagCryptoPlugin, self).tearDown()
        if not imports_ok:
            return
        self.patcher.stop()
        os.rmdir(self.nss_dir)

    def test_generate(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "AES"
        generate_dto = plugin_import.GenerateDTO(
            plugin_import.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
            secret.algorithm,
            secret.bit_length,
            None)
        self.plugin.generate_symmetric(
            generate_dto,
            mock.MagicMock(),
            mock.MagicMock()
        )

        self.keyclient_mock.generate_symmetric_key.assert_called_once_with(
            mock.ANY,
            secret.algorithm.upper(),
            secret.bit_length,
            mock.ANY)

    def test_generate_non_supported_algorithm(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "hmacsha256"
        generate_dto = plugin_import.GenerateDTO(
            plugin_import.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
            secret.algorithm,
            secret.bit_length,
            None)
        self.assertRaises(
            DogtagPluginAlgorithmException,
            self.plugin.generate_symmetric,
            generate_dto,
            mock.MagicMock(),
            mock.MagicMock()
        )

    def test_raises_error_with_no_pem_path(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_crypto_plugin = mock.MagicMock(pem_path=None)
        self.assertRaises(
            ValueError,
            DogtagCryptoPlugin,
            m,
        )

    def test_raises_error_with_no_pem_password(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_crypto_plugin = mock.MagicMock(pem_password=None)
        self.assertRaises(
            ValueError,
            DogtagCryptoPlugin,
            m,
        )

    def test_raises_error_with_no_nss_password(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_crypto_plugin = mock.MagicMock(nss_password=None)
        self.assertRaises(
            ValueError,
            DogtagCryptoPlugin,
            m,
        )

    def test_encrypt(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        payload = 'encrypt me!!'
        encrypt_dto = plugin_import.EncryptDTO(payload)
        _cyphertext, _kek_meta_extended = self.plugin.encrypt(encrypt_dto,
                                                              mock.MagicMock(),
                                                              mock.MagicMock())
        self.keyclient_mock.archive_key.assert_called_once_with(
            mock.ANY,
            "passPhrase",
            payload,
            key_algorithm=None,
            key_size=None)

    def test_decrypt(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_id = 'key1'
        decrypt_dto = plugin_import.DecryptDTO(key_id)
        self.plugin.decrypt(decrypt_dto,
                            mock.MagicMock(),
                            mock.MagicMock(),
                            mock.MagicMock())

        self.keyclient_mock.retrieve_key.assert_called_once_with(key_id)

    def test_supports_encrypt_decrypt(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        self.assertTrue(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.ENCRYPT_DECRYPT
            )
        )

    def test_supports_symmetric_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        self.assertTrue(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.SYMMETRIC_KEY_GENERATION
            )
        )

    def test_supports_symmetric_hmacsha256_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        self.assertFalse(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
                'hmacsha256', 128
            )
        )

    def test_supports_asymmetric_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        self.assertFalse(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION
            )
        )

    def test_does_not_support_unknown_type(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        self.assertFalse(
            self.plugin.supports("SOMETHING_RANDOM")
        )
