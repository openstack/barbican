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
from oslo.config import cfg

from barbican.openstack.common import jsonutils as json
from barbican.openstack.common.gettextutils import _


CONF = cfg.CONF

simple_crypto_plugin_group = cfg.OptGroup(name='simple_crypto_plugin',
                                          title="Simple Crypto Plugin Options")
simple_crypto_plugin_opts = [
    cfg.StrOpt('kek',
               default=b'sixteen_byte_key',
               help=_('Key encryption key to be used by Simple Crypto Plugin'))
]
CONF.register_group(simple_crypto_plugin_group)
CONF.register_opts(simple_crypto_plugin_opts, group=simple_crypto_plugin_group)


class CryptoPluginBase(object):
    """Base class for Crypto plugins."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encrypt(self, unencrypted, tenant):
        """Encrypt unencrypted data in the context of the provided tenant.

        :param unencrypted: byte data to be encrypted.
        :param tenant: Tenant associated with the unencrypted data.
        :returns: tuple -- contains the encrypted data and kek metadata.
        :raises: ValueError if unencrypted is not byte data.

        """

    @abc.abstractmethod
    def decrypt(self, encrypted, kek_metadata, tenant):
        """Decrypt encrypted_datum in the context of the provided tenant.

        :param encrypted: cyphertext to be decrypted.
        :param kek_metadata: metadata that was created by encryption.
        :param tenant: Tenant associated with the encrypted datum.
        :returns: str -- unencrypted byte data

        """

    @abc.abstractmethod
    def create(self, algorithm, bit_length):
        """Create a new key."""

    @abc.abstractmethod
    def supports(self, kek_metadata):
        """Used to decide whether the plugin supports decoding the secret."""


class SimpleCryptoPlugin(CryptoPluginBase):
    """Insecure implementation of the crypto plugin."""

    def __init__(self, conf=CONF):
        self.kek = conf.simple_crypto_plugin.kek
        self.block_size = AES.block_size

    def _pad(self, unencrypted):
        """Adds padding to unencrypted byte string."""
        pad_length = self.block_size - (
            len(unencrypted) % self.block_size
        )
        return unencrypted + (chr(pad_length) * pad_length)

    def _strip_pad(self, unencrypted):
        pad_length = ord(unencrypted[-1:])
        unpadded = unencrypted[:-pad_length]
        return unpadded

    def encrypt(self, unencrypted, tenant):
        if not isinstance(unencrypted, str):
            raise ValueError('Unencrypted data must be a byte type, '
                             'but was {0}'.format(type(unencrypted)))
        padded_data = self._pad(unencrypted)
        iv = Random.get_random_bytes(self.block_size)
        encryptor = AES.new(self.kek, AES.MODE_CBC, iv)

        cyphertext = iv + encryptor.encrypt(padded_data)
        kek_metadata = json.dumps({
            'plugin': 'SimpleCryptoPlugin',
            'encryption': 'aes-128-cbc',
            'kek': 'kek_id'
        })

        return cyphertext, kek_metadata

    def decrypt(self, encrypted, kek_metadata, tenant):
        iv = encrypted[:self.block_size]
        cypher_text = encrypted[self.block_size:]
        decryptor = AES.new(self.kek, AES.MODE_CBC, iv)
        padded_secret = decryptor.decrypt(cypher_text)
        return self._strip_pad(padded_secret)

    def create(self, algorithm, bit_length):
        # TODO: do this right
        # return Random.get_random_bytes(bit_length/8)
        if bit_length == 256:
            return (b"r\x07\xb7\xfc\xe8\xae\x99\x94\xce_I\xaftM\xb3T'\x1c\xa2"
                    b"\xd5\xeb\x03p\x17\xb8\r\xddA\xf9\xa3\x08W")
        elif bit_length == 192:
            return (b"\xb7^\xc5\xc9Ey\xc3\x88-\xad\x8d\xd2\xad{\x96\xba#\x973"
                    b"\xe0ZY\xe5\x1e")
        elif bit_length == 128:
            return b",q\x90M\xbc)6AbjUx2t(C"
        else:
            raise ValueError('At this time you must supply 128/192/256 as'
                             'bit length')

    def supports(self, kek_metadata):
        metadata = json.loads(kek_metadata)
        return metadata['plugin'] == 'SimpleCryptoPlugin'
