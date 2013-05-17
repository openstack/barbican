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

import abc

from Crypto.Cipher import AES
from Crypto import Random

from barbican.model.models import EncryptedDatum
from barbican.openstack.common import jsonutils as json


class CryptoPluginBase(object):
    """Base class for Crypto plugins."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encrypt(self, unencrypted, secret, tenant):
        """Encrypt unencrypted data in the context of the provided
        secret and tenant"""

    @abc.abstractmethod
    def decrypt(self, secret_type, secret, tenant):
        """Decrypt secret into secret_type in the context of the
        provided tenant"""

    @abc.abstractmethod
    def create(self, secret_type):
        """Create a new key."""

    @abc.abstractmethod
    def supports(self, secret_type):
        """Whether the plugin supports the specified secret type."""


class SimpleCryptoPlugin(CryptoPluginBase):
    """Insecure implementation of the crypto plugin."""

    def __init__(self):
        self.supported_types = ['text/plain', 'application/octet-stream']
        self.kek = u'sixteen_byte_key'
        self.block_size = 16

    def _pad(self, unencrypted):
        try:
            unencrypted_bytes = unencrypted.encode('utf-8')
        except UnicodeDecodeError:
            unencrypted_bytes = unencrypted
        pad_length = self.block_size - (
            len(unencrypted_bytes) % self.block_size
        )
        return unencrypted_bytes + (chr(pad_length) * pad_length)

    def _strip_pad(self, unencrypted):
        try:
            unencrypted_bytes = unencrypted.encode('utf-8')
        except UnicodeDecodeError:
            unencrypted_bytes = unencrypted
        pad_length = ord(unencrypted_bytes[-1:])
        unpadded = unencrypted_bytes[:-pad_length]
        try:
            #TODO: maybe kek_metadata needs to be used to determine
            # whether the unpadded byte stream is a utf-8 string or not?
            unpadded = unpadded.decode('utf-8')
        except UnicodeDecodeError:
            pass
        return unpadded

    def encrypt(self, unencrypted, secret, tenant):
        padded_data = self._pad(unencrypted)
        iv = Random.get_random_bytes(16)
        encryptor = AES.new(self.kek, AES.MODE_CBC, iv)
        cyphertext = iv + encryptor.encrypt(padded_data)

        datum = EncryptedDatum(secret)
        datum.cypher_text = cyphertext
        datum.kek_metadata = json.dumps({
            'plugin': 'SimpleCryptoPlugin',
            'encryption': 'aes-128-cbc',
            'kek': 'kek_id'
        })
        return datum

    def decrypt(self, secret_type, secret, tenant):
        payload = secret.encrypted_data.cypher_text
        iv = payload[:16]
        cypher_text = payload[16:]
        decryptor = AES.new(self.kek, AES.MODE_CBC, iv)
        padded_secret = decryptor.decrypt(cypher_text)
        return self._strip_pad(padded_secret)

    def create(self, secret_type):
        # TODO:
        return "insecure_key"

    def supports(self, secret_type):
        return secret_type in self.supported_types
