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
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Util import asn1

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

    def generate_symmetric(self, generate_dto, kek_meta_dto, keystone_id):
        return plugin.ResponseDTO("encrypted insecure key", None)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, keystone_id):
        return (plugin.ResponseDTO('insecure_private_key', None),
                plugin.ResponseDTO('insecure_public_key', None),
                None)

    def supports(self, type_enum, algorithm=None, bit_length=None, mode=None):
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
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           MagicMock(),
                                           MagicMock())
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        decrypted = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                        response_dto.kek_meta_extended,
                                        MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_random_bytes_encryption(self):
        unencrypted = Random.get_random_bytes(10)
        encrypt_dto = plugin.EncryptDTO(unencrypted)
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           MagicMock(),
                                           MagicMock())
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        decrypted = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                        response_dto.kek_meta_extended,
                                        MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_generate_256_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 256
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            secret.mode, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  response_dto.kek_meta_extended, MagicMock())
        self.assertEqual(len(key), 32)

    def test_generate_192_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 192
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  response_dto.kek_meta_extended, MagicMock())
        self.assertEqual(len(key), 24)

    def test_generate_128_bit_key(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "AES"
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  response_dto.kek_meta_extended, MagicMock())
        self.assertEqual(len(key), 16)

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
        kek_metadata_dto = MagicMock()
        kek_metadata_dto = self.plugin.bind_kek_metadata(kek_metadata_dto)

        self.assertEqual(kek_metadata_dto.algorithm, 'aes')
        self.assertEqual(kek_metadata_dto.bit_length, 128)
        self.assertEqual(kek_metadata_dto.mode, 'cbc')
        self.assertIsNone(kek_metadata_dto.plugin_meta)

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

    def test_generate_512_bit_RSA_key(self):
        generate_dto = plugin.GenerateDTO('rsa', 512, None, None)
        self.assertRaises(ValueError,
                          self.plugin.generate_asymmetric,
                          generate_dto,
                          MagicMock(),
                          MagicMock())

    def test_generate_2048_bit_DSA_key(self):
        generate_dto = plugin.GenerateDTO('dsa', 2048, None, None)
        self.assertRaises(ValueError, self.plugin.generate_asymmetric,
                          generate_dto,
                          MagicMock(),
                          MagicMock())

    def test_generate_2048_bit_DSA_key_with_passphrase(self):
        generate_dto = plugin.GenerateDTO('dsa', 2048, None, 'Passphrase')
        self.assertRaises(ValueError, self.plugin.generate_asymmetric,
                          generate_dto,
                          MagicMock(),
                          MagicMock())

    def test_generate_asymmetric_1024_bit_key(self):
        generate_dto = plugin.GenerateDTO('rsa', 1024, None, None)

        private_dto, public_dto, passwd_dto = self.plugin.generate_asymmetric(
            generate_dto, MagicMock(), MagicMock())

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          MagicMock(),
                                          private_dto.kek_meta_extended,
                                          MagicMock())

        decrypt_dto = plugin.DecryptDTO(public_dto.cypher_text)
        public_dto = self.plugin.decrypt(decrypt_dto,
                                         MagicMock(),
                                         public_dto.kek_meta_extended,
                                         MagicMock())

        public_dto = RSA.importKey(public_dto)
        private_dto = RSA.importKey(private_dto)
        self.assertEqual(public_dto.size(), 1023)
        self.assertEqual(private_dto.size(), 1023)
        self.assertTrue(private_dto.has_private)

    def test_generate_1024_bit_RSA_key_in_pem(self):
        generate_dto = plugin.GenerateDTO('rsa', 1024, None, 'changeme')

        private_dto, public_dto, passwd_dto = \
            self.plugin.generate_asymmetric(generate_dto,
                                            MagicMock(),
                                            MagicMock())
        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          MagicMock(),
                                          private_dto.kek_meta_extended,
                                          MagicMock())

        private_dto = RSA.importKey(private_dto, 'changeme')
        self.assertTrue(private_dto.has_private())

    def test_generate_1024_DSA_key_in_pem_and_reconstruct_key_der(self):
        generate_dto = plugin.GenerateDTO('dsa', 1024, None, None)

        private_dto, public_dto, passwd_dto = \
            self.plugin.generate_asymmetric(generate_dto,
                                            MagicMock(),
                                            MagicMock())

        decrypt_dto = plugin.DecryptDTO(private_dto.cypher_text)
        private_dto = self.plugin.decrypt(decrypt_dto,
                                          MagicMock(),
                                          private_dto.kek_meta_extended,
                                          MagicMock())

        prv_seq = asn1.DerSequence()
        data = "\n".join(private_dto.strip().split("\n")
                         [1:-1]).decode("base64")
        prv_seq.decode(data)
        p, q, g, y, x = prv_seq[1:]

        private_dto = DSA.construct((y, g, p, q, x))
        self.assertTrue(private_dto.has_private())

    def test_generate_128_bit_hmac_key(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = "hmacsha256"
        generate_dto = plugin.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        response_dto = self.plugin.generate_symmetric(
            generate_dto,
            MagicMock(),
            MagicMock()
        )
        decrypt_dto = plugin.DecryptDTO(response_dto.cypher_text)
        key = self.plugin.decrypt(decrypt_dto, MagicMock(),
                                  response_dto.kek_meta_extended, MagicMock())
        self.assertEqual(len(key), 16)
