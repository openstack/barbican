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

from Crypto import Random
from mock import MagicMock

import testtools

from barbican.crypto import plugin
from barbican.model import models


class TestCryptoPlugin(plugin.CryptoPluginBase):
    """Crypto plugin implementation for testing the plugin manager."""

    def encrypt(self, encrypt_dto, kek_meta_dto, keystone_id):
        cypher_text = b'cypher_text'
        return cypher_text, None

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                keystone_id):
        return b'unencrypted_data'

    def bind_kek_metadata(self, kek_meta_dto):
        kek_meta_dto.algorithm = 'aes'
        kek_meta_dto.bit_length = 128
        kek_meta_dto.mode = 'cbc'
        kek_meta_dto.plugin_meta = None
        return kek_meta_dto

    def generate(self, generate_dto, kek_meta_dto, keystone_id):
        return "encrypted insecure key", None

    def supports(self, type_enum, algorithm=None, mode=None):
        if type_enum == plugin.PluginSupportTypes.ENCRYPT_DECRYPT:
            return True
        elif type_enum == plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return True
        else:
            return False


class WhenTestingSimpleCryptoPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingSimpleCryptoPlugin, self).setUp()
        self.plugin = plugin.SimpleCryptoPlugin()

    def test_pad_binary_string(self):
        binary_string = b'some_binary_string'
        padded_string = (
            b'some_binary_string' +
            b'\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
        )
        self.assertEqual(self.plugin._pad(binary_string), padded_string)

    def test_pad_random_bytes(self):
        random_bytes = Random.get_random_bytes(10)
        padded_bytes = random_bytes + b'\x06\x06\x06\x06\x06\x06'
        self.assertEqual(self.plugin._pad(random_bytes), padded_bytes)

    def test_strip_padding_from_binary_string(self):
        binary_string = b'some_binary_string'
        padded_string = (
            b'some_binary_string' +
            b'\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
        )
        self.assertEqual(self.plugin._strip_pad(padded_string), binary_string)

    def test_strip_padding_from_random_bytes(self):
        random_bytes = Random.get_random_bytes(10)
        padded_bytes = random_bytes + b'\x06\x06\x06\x06\x06\x06'
        self.assertEqual(self.plugin._strip_pad(padded_bytes), random_bytes)

    def test_encrypt_unicode_raises_value_error(self):
        unencrypted = u'unicode_beer\U0001F37A'
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        secret = MagicMock()
        secret.mime_type = 'text/plain'
        self.assertRaises(
            ValueError,
            self.plugin.encrypt,
            encrypt_dto,
            MagicMock(),
            MagicMock(),
        )

    def test_byte_string_encryption(self):
        unencrypted = b'some_secret'
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        encrypted, kek_ext = self.plugin.encrypt(encrypt_dto,
                                                 MagicMock(),
                                                 MagicMock())
        decrypt_dto = plugin.DecryptDTO(encrypted)
        decrypted = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                        kek_ext, MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_random_bytes_encryption(self):
        unencrypted = Random.get_random_bytes(10)
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        encrypted, kek_meta_ext = self.plugin.encrypt(encrypt_dto,
                                                      MagicMock(), MagicMock())
        decrypt_dto = plugin.DecryptDTO(encrypted)
        decrypted = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                        kek_meta_ext, MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_generate_256_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 256
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
            secret.algorithm,
            secret.bit_length,
            secret.mode)
        encrypted, kek_ext = self.plugin.generate(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(encrypted)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  kek_ext, MagicMock())
        self.assertEqual(len(key), 32)

    def test_generate_192_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 192
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
            secret.algorithm,
            secret.bit_length,
            None)
        encrypted, kek_ext = self.plugin.generate(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(encrypted)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  kek_ext, MagicMock())
        self.assertEqual(len(key), 24)

    def test_generate_128_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
            secret.algorithm,
            secret.bit_length,
            None)
        encrypted, kek_ext = self.plugin.generate(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(encrypted)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  kek_ext, MagicMock())
        self.assertEqual(len(key), 16)

    def test_supports_encrypt_decrypt(self):
        self.assertTrue(
            self.plugin.supports(plugin.PluginSupportTypes.ENCRYPT_DECRYPT)
        )

    def test_supports_symmetric_key_generation(self):
        self.assertTrue(
            self.plugin.supports(
                plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION)
        )

    def test_does_not_support_unknown_type(self):
        self.assertFalse(
            self.plugin.supports("SOMETHING_RANDOM")
        )

    def test_bind_kek_metadata(self):
        kek_metadata_dto = MagicMock()
        kek_metadata_dto = self.plugin.bind_kek_metadata(kek_metadata_dto)

        self.assertEqual(kek_metadata_dto.algorithm, 'aes')
        self.assertEqual(kek_metadata_dto.bit_length, 128)
        self.assertEqual(kek_metadata_dto.mode, 'cbc')
        self.assertIsNone(kek_metadata_dto.plugin_meta)
