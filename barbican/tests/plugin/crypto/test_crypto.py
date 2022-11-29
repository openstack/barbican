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

import os
from unittest import mock

from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from barbican.model import models
from barbican.plugin.crypto import base as plugin
from barbican.plugin.crypto import simple_crypto as simple
from barbican.tests import utils


class WhenTestingSimpleCryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSimpleCryptoPlugin, self).setUp()
        self.plugin = simple.SimpleCryptoPlugin()

    def _get_mocked_kek_meta_dto(self):
        # For SimpleCryptoPlugin, per-project KEKs are stored in
        # kek_meta_dto.plugin_meta. SimpleCryptoPlugin does a get-or-create
        # on the plugin_meta field, so plugin_meta should be None initially.
        kek_meta_dto = plugin.KEKMetaDTO(mock.MagicMock())
        kek_meta_dto.plugin_meta = None
        return self.plugin.bind_kek_metadata(kek_meta_dto)

    def test_encrypt_unicode_raises_value_error(self):
        unencrypted = 'unicode_beer\U0001F37A'
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        secret = mock.MagicMock()
        secret.mime_type = 'text/plain'
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        self.assertRaises(
            ValueError,
            self.plugin.encrypt,
            encrypt_dto,
            kek_meta_dto,
            mock.MagicMock(),
        )

    def test_encrypt_with_unicode_kek_must_pass(self):
        """Test plan:

                Generate a kek
                Encrypt with master kek
                Convert to unicode
                call plugin.encrypt on unencrypted
                decrypt response cypher_text
                Compare with unencrypted
        """
        project_kek = fernet.Fernet.generate_key()
        encryptor = fernet.Fernet(self.plugin.master_kek)
        ENC_project_kek = encryptor.encrypt(project_kek)
        UENC_project_kek = ENC_project_kek
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        kek_meta_dto.plugin_meta = UENC_project_kek

        unencrypted = b'PlainTextSecret'
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           kek_meta_dto,
                                           mock.MagicMock())

        project_encryptor = fernet.Fernet(project_kek)
        decrypted = project_encryptor.decrypt(response_dto.cypher_text)
        self.assertEqual(unencrypted, decrypted)

    def test_decrypt_kek_not_created(self):
        kek_meta_dto = mock.MagicMock()
        kek_meta_dto.plugin_meta = None
        self.assertRaises(
            ValueError,
            self.plugin.decrypt,
            mock.MagicMock(),
            kek_meta_dto,
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_byte_string_encryption(self):
        unencrypted = b'some_secret'
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           kek_meta_dto,
                                           mock.MagicMock())
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        decrypted = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                        response_dto.kek_meta_extended,
                                        mock.MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_random_bytes_encryption(self):
        unencrypted = os.urandom(10)
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           kek_meta_dto,
                                           mock.MagicMock())
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        decrypted = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                        response_dto.kek_meta_extended,
                                        mock.MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_generate_256_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 256
        secret.algorithm = "AES"
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            secret.mode, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                  response_dto.kek_meta_extended,
                                  mock.MagicMock())
        self.assertEqual(32, len(key))

    def test_generate_192_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 192
        secret.algorithm = "AES"
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                  response_dto.kek_meta_extended,
                                  mock.MagicMock())
        self.assertEqual(24, len(key))

    def test_generate_128_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "AES"
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                  response_dto.kek_meta_extended,
                                  mock.MagicMock())
        self.assertEqual(16, len(key))

    def test_supports_encrypt_decrypt(self):
        self.assertTrue(
            self.plugin.supports(plugin.PluginSupportTypes.ENCRYPT_DECRYPT)
        )

    def test_supports_symmetric_key_generation(self):
        self.assertTrue(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION, 'AES', 64)
        )
        self.assertFalse(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION, 'AES')
        )
        self.assertTrue(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
                'hmacsha512', 128)
        )
        self.assertFalse(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
                'hmacsha512', 12)
        )
        self.assertFalse(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
                'Camillia', 128)
        )

    def test_does_not_support_unknown_type(self):
        self.assertFalse(
            self.plugin.supports("SOMETHING_RANDOM")
        )

    def test_bind_kek_metadata(self):
        kek_metadata_dto = mock.MagicMock()
        kek_metadata_dto = self.plugin.bind_kek_metadata(kek_metadata_dto)

        self.assertEqual('aes', kek_metadata_dto.algorithm)
        self.assertEqual(128, kek_metadata_dto.bit_length)
        self.assertEqual('cbc', kek_metadata_dto.mode)

    def test_supports_asymmetric_key_generation(self):
        self.assertTrue(
            self.plugin.supports(
                plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION,
                'DSA', 1024)
        )
        self.assertTrue(
            self.plugin.supports(
                plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION,
                "RSA", 1024)
        )
        self.assertFalse(
            self.plugin.supports(
                plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION,
                "DSA", 512)
        )
        self.assertFalse(
            self.plugin.supports(
                plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION,
                "RSA", 64)
        )

    def test_generate_asymmetric_1024_bit_key(self):
        generate_dto = plugin.GenerateDTO('rsa', 1024, None, None)
        kek_meta_dto = self._get_mocked_kek_meta_dto()

        private_dto, public_dto, passwd_dto = self.plugin.generate_asymmetric(
            generate_dto, kek_meta_dto, mock.MagicMock())

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          kek_meta_dto,
                                          private_dto.kek_meta_extended,
                                          mock.MagicMock())

        decrypt_dto = plugin.DecryptDTO(public_dto.cypher_text)
        public_dto = self.plugin.decrypt(decrypt_dto,
                                         kek_meta_dto,
                                         public_dto.kek_meta_extended,
                                         mock.MagicMock())

        # check we can reload the private and public keys
        private_key = serialization.load_pem_private_key(
            data=private_dto,
            password=None,
            backend=default_backend()
        )

        public_key = serialization.load_pem_public_key(
            data=public_dto,
            backend=default_backend()
        )

        self.assertEqual(1024, private_key.key_size)
        self.assertEqual(1024, public_key.key_size)

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        # get the public key from the private key we recovered to compare
        recovered_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        self.assertTrue(public_key == recovered_key)

    def test_generate_1024_bit_RSA_key_with_passphrase(self):
        generate_dto = plugin.GenerateDTO('rsa', 1024, None, 'changeme')
        kek_meta_dto = self._get_mocked_kek_meta_dto()

        private_dto, public_dto, passwd_dto = self.plugin.generate_asymmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          kek_meta_dto,
                                          private_dto.kek_meta_extended,
                                          mock.MagicMock())

        decrypt_dto = plugin.DecryptDTO(public_dto.cypher_text)
        public_dto = self.plugin.decrypt(decrypt_dto,
                                         kek_meta_dto,
                                         public_dto.kek_meta_extended,
                                         mock.MagicMock())

        # check we can reload the private and public keys
        private_key = serialization.load_pem_private_key(
            data=private_dto,
            password='changeme'.encode(),
            backend=default_backend()
        )

        public_key = serialization.load_pem_public_key(
            data=public_dto,
            backend=default_backend()
        )

        self.assertEqual(1024, private_key.key_size)
        self.assertEqual(1024, public_key.key_size)

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        # get the public key from the private key we recovered to compare
        recovered_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        self.assertTrue(public_key == recovered_key)

    def test_generate_1024_bit_DSA_key_with_passphrase(self):
        generate_dto = plugin.GenerateDTO('dsa', 1024, None, 'changeme')
        kek_meta_dto = self._get_mocked_kek_meta_dto()

        private_dto, public_dto, passwd_dto = self.plugin.generate_asymmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          kek_meta_dto,
                                          private_dto.kek_meta_extended,
                                          mock.MagicMock())

        decrypt_dto = plugin.DecryptDTO(public_dto.cypher_text)
        public_dto = self.plugin.decrypt(decrypt_dto,
                                         kek_meta_dto,
                                         public_dto.kek_meta_extended,
                                         mock.MagicMock())

        # check we can reload the private and public keys
        private_key = serialization.load_der_private_key(
            data=private_dto,
            password='changeme'.encode(),
            backend=default_backend()
        )

        public_key = serialization.load_der_public_key(
            data=public_dto,
            backend=default_backend()
        )

        self.assertEqual(1024, private_key.key_size)
        self.assertEqual(1024, public_key.key_size)

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # get the public key from the private key we recovered to compare
        recovered_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.assertTrue(public_key == recovered_key)

    def test_generate_1024_DSA_key_in_pem_and_reconstruct_key_der(self):
        generate_dto = plugin.GenerateDTO('dsa', 1024, None, None)
        kek_meta_dto = self._get_mocked_kek_meta_dto()

        private_dto, public_dto, passwd_dto = self.plugin.generate_asymmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          kek_meta_dto,
                                          private_dto.kek_meta_extended,
                                          mock.MagicMock())

        private_key = serialization.load_der_private_key(
            data=private_dto,
            password=None,
            backend=default_backend()
        )

        self.assertEqual(1024, private_key.key_size)

    def test_generate_128_bit_hmac_key(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "hmacsha256"
        kek_meta_dto = self._get_mocked_kek_meta_dto()
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            kek_meta_dto,
            mock.MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, kek_meta_dto,
                                  response_dto.kek_meta_extended,
                                  mock.MagicMock())
        self.assertEqual(16, len(key))

    def test_get_plugin_name(self):
        self.assertIsNotNone(self.plugin.get_plugin_name())
