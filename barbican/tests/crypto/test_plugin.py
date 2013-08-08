# Copyright (c) 2013 Rackspace, Inc.
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
import unittest

from barbican.crypto.plugin import CryptoPluginBase, SimpleCryptoPlugin
from barbican.openstack.common import jsonutils as json


class TestCryptoPlugin(CryptoPluginBase):
    """Crypto plugin implementation for testing the plugin manager."""

    def encrypt(self, unencrypted, kek_metadata, tenant):
        cypher_text = 'cypher_text'
        return cypher_text, None

    def decrypt(self, encrypted, kek_meta_tenant, kek_meta_extended, tenant):
        return b'unencrypted_data'

    def bind_kek_metadata(self, kek_metadata):
        kek_metadata.algorithm = 'aes'
        kek_metadata.bit_length = 128
        kek_metadata.mode = 'cbc'
        kek_metadata.plugin_meta = None

    def create(self, algorithm, bit_length):
        return "insecure_key"

    def supports(self, kek_metadata):
        metadata = json.loads(kek_metadata)
        return metadata['plugin'] == 'TestCryptoPlugin'


class WhenTestingSimpleCryptoPlugin(unittest.TestCase):

    def setUp(self):
        self.plugin = SimpleCryptoPlugin()

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
        secret = MagicMock()
        secret.mime_type = 'text/plain'
        with self.assertRaises(ValueError):
            self.plugin.encrypt(unencrypted, MagicMock(), MagicMock())

    def test_byte_string_encryption(self):
        unencrypted = b'some_secret'
        encrypted, kek_ext = self.plugin.encrypt(unencrypted,
                                                 MagicMock(),
                                                 MagicMock())
        decrypted = self.plugin.decrypt(encrypted, MagicMock(),
                                        kek_ext, MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_random_bytes_encryption(self):
        unencrypted = Random.get_random_bytes(10)
        encrypted, kek_meta_ext = self.plugin.encrypt(unencrypted,
                                                      MagicMock(), MagicMock())
        decrypted = self.plugin.decrypt(encrypted, MagicMock(),
                                        kek_meta_ext, MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_create_256_bit_key(self):
        key = self.plugin.create("aes", 256)
        self.assertEqual(len(key), 32)

    def test_create_192_bit_key(self):
        key = self.plugin.create("aes", 192)
        self.assertEqual(len(key), 24)

    def test_create_128_bit_key(self):
        key = self.plugin.create("aes", 128)
        self.assertEqual(len(key), 16)

    def test_create_unsupported_bit_key(self):
        with self.assertRaises(ValueError):
            self.plugin.create("aes", 129)

    def test_supports_decoding_metadata(self):
        kek_metadata = json.dumps({
            'plugin': 'SimpleCryptoPlugin',
            'encryption': 'aes-128-cbc',
            'kek': 'kek_id'
        })
        self.assertTrue(self.plugin.supports(kek_metadata))
