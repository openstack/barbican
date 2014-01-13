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

import abc

from Crypto.Cipher import AES
from Crypto import Random
from oslo.config import cfg

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


class PluginSupportTypes(object):
    """Class to hold the type enumeration that plugins may support."""
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    SYMMETRIC_KEY_GENERATION = "SYMMETRIC_KEY_GENERATION"
    # A list of symmetric algorithms that are used to determine type of key gen
    SYMMETRIC_ALGORITHMS = ['aes', 'des']


class KEKMetaDTO(object):
    """
    Data transfer object to support key encryption key (KEK) definition.

    Instances are passed into third-party plugins rather than passing in
    KekDatum instances directly. This provides a level of isolation from
    these third party systems and Barbican's data model.
    """

    def __init__(self, kek_datum):
        """
        kek_datum is typically a barbican.model.models.EncryptedDatum instance.
        """
        self.kek_label = kek_datum.kek_label
        self.plugin_name = kek_datum.plugin_name
        self.algorithm = kek_datum.algorithm
        self.bit_length = kek_datum.bit_length
        self.mode = kek_datum.mode
        self.plugin_meta = kek_datum.plugin_meta


def indicate_bind_completed(kek_meta_dto, kek_datum):
    """
    Updates the supplied kek_datum instance per the contents of the supplied
    kek_meta_dto instance. This function is typically used once plugins have
    had a chance to bind kek_meta_dto to their crypto systems.

    :param kek_meta_dto:
    :param kek_datum:
    :return: None

    """
    kek_datum.bind_completed = True
    kek_datum.algorithm = kek_meta_dto.algorithm
    kek_datum.bit_length = kek_meta_dto.bit_length
    kek_datum.mode = kek_meta_dto.mode
    kek_datum.plugin_meta = kek_meta_dto.plugin_meta


class CryptoPluginBase(object):
    """Base class for Crypto plugins."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encrypt(self, unencrypted, kek_meta_dto, keystone_id):
        """Encrypt unencrypted data in the context of the provided tenant.

        :param unencrypted: byte data to be encrypted.
        :param kek_meta_dto: Key encryption key metadata to use for encryption.
        :param keystone_id: keystone_id associated with the unencrypted data.
        :returns: encrypted data and kek_meta_extended, the former the
        resultant cypher text, the latter being optional per-secret metadata
        needed to decrypt (over and above the per-tenant metadata managed
        outside of the plugins)

        """

    @abc.abstractmethod
    def decrypt(self, encrypted, kek_meta_dto, kek_meta_extended, keystone_id):
        """Decrypt encrypted_datum in the context of the provided tenant.

        :param encrypted: cyphertext to be decrypted.
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param kek_meta_extended: Optional per-secret KEK metadata to use for
        decryption.
        :param keystone_id: keystone_id associated with the encrypted datum.
        :returns: str -- unencrypted byte data

        """

    @abc.abstractmethod
    def bind_kek_metadata(self, kek_meta_dto):
        """
        Bind a key encryption key (KEK) metadata to the sub-system
        handling encryption/decryption, updating information about the
        key encryption key (KEK) metadata in the supplied 'kek_metadata'
        data-transfer-object instance, and then returning this instance.

        This method is invoked prior to the encrypt() method above.
        Implementors should fill out the supplied 'kek_meta_dto' instance
        (an instance of KEKMetadata above) as needed to completely describe
        the kek metadata and to complete the binding process. Barbican will
        persist the contents of this instance once this method returns.

        :param kek_meta_dto: Key encryption key metadata to bind, with the
               'kek_label' attribute guaranteed to be unique, and the
               and 'plugin_name' attribute already configured.
        :returns: kek_meta_dto: Returns the specified DTO, after
                  modifications.
        """

    @abc.abstractmethod
    def create(self, bit_length, type_enum, algorithm=None, mode=None):
        """Create a new key."""

    @abc.abstractmethod
    def supports(self, type_enum, algorithm=None, mode=None):
        """Used to determine if the plugin supports the requested operation.

        :param type_enum: Enumeration from PluginSupportsType class
        :param algorithm: String algorithm name if needed
        """


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

    def encrypt(self, unencrypted, kek_meta_dto, keystone_id):
        if not isinstance(unencrypted, str):
            raise ValueError('Unencrypted data must be a byte type, '
                             'but was {0}'.format(type(unencrypted)))
        padded_data = self._pad(unencrypted)
        iv = Random.get_random_bytes(self.block_size)
        encryptor = AES.new(self.kek, AES.MODE_CBC, iv)

        cyphertext = iv + encryptor.encrypt(padded_data)

        return cyphertext, None

    def decrypt(self, encrypted, kek_meta_dto, kek_meta_extended, keystone_id):
        iv = encrypted[:self.block_size]
        cypher_text = encrypted[self.block_size:]
        decryptor = AES.new(self.kek, AES.MODE_CBC, iv)
        padded_secret = decryptor.decrypt(cypher_text)
        return self._strip_pad(padded_secret)

    def bind_kek_metadata(self, kek_meta_dto):
        kek_meta_dto.algorithm = 'aes'
        kek_meta_dto.bit_length = 128
        kek_meta_dto.mode = 'cbc'
        kek_meta_dto.plugin_meta = None
        return kek_meta_dto

    def create(self, bit_length, type_enum, algorithm=None, mode=None):
        byte_length = bit_length / 8
        return Random.get_random_bytes(byte_length)

    def supports(self, type_enum, algorithm=None, mode=None):
        if type_enum == PluginSupportTypes.ENCRYPT_DECRYPT:
            return True
        elif type_enum == PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return True
        else:
            return False
