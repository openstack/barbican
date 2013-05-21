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
from barbican.model.models import EncryptedDatum
from barbican.openstack.common import jsonutils as json


class TestCryptoPlugin(CryptoPluginBase):
    """Crypto plugin implementation for testing the plugin manager."""

    def encrypt(self, unencrypted, secret, tenant):
        datum = EncryptedDatum(secret)
        datum.cypher_text = 'cypher_text'
        datum.kek_metadata = json.dumps({'plugin': 'TestCryptoPlugin'})
        return datum

    def decrypt(self, encrypted_datum, tenant):
        return 'plain-data'

    def create(self, secret_type):
        return "insecure_key"

    def supports(self, secret_type):
        return secret_type == 'text/plain'


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
            self.plugin.encrypt(unencrypted, secret, MagicMock())

    def test_byte_string_encryption(self):
        unencrypted = b'some_secret'
        secret = MagicMock()
        secret.mime_type = 'text/plain'
        encrypted_datum = self.plugin.encrypt(unencrypted, secret, MagicMock())
        decrypted = self.plugin.decrypt(encrypted_datum, MagicMock())
        self.assertEqual(unencrypted, decrypted)

    def test_random_bytes_encryption(self):
        unencrypted = Random.get_random_bytes(10)
        secret = MagicMock()
        secret.mime_type = 'text/plain'
        encrypted_datum = self.plugin.encrypt(unencrypted, secret, MagicMock())
        decrypted = self.plugin.decrypt(encrypted_datum, MagicMock())
        self.assertEqual(unencrypted, decrypted)
