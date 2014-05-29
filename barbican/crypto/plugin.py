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
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import asn1

from oslo.config import cfg

import six

from barbican.common import utils
from barbican.openstack.common import gettextutils as u

LOG = utils.getLogger(__name__)

CONF = cfg.CONF

simple_crypto_plugin_group = cfg.OptGroup(name='simple_crypto_plugin',
                                          title="Simple Crypto Plugin Options")
simple_crypto_plugin_opts = [
    cfg.StrOpt('kek',
               default=b'sixteen_byte_key',
               help=u._('Key encryption key to be used by Simple Crypto '
                        'Plugin'))
]
CONF.register_group(simple_crypto_plugin_group)
CONF.register_opts(simple_crypto_plugin_opts, group=simple_crypto_plugin_group)


class PluginSupportTypes(object):
    """Class to hold the type enumeration that plugins may support."""
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    SYMMETRIC_KEY_GENERATION = "SYMMETRIC_KEY_GENERATION"
    # A list of symmetric algorithms that are used to determine type of key gen
    SYMMETRIC_ALGORITHMS = ['aes', 'des', '3des', 'hmacsha1',
                            'hmacsha256', 'hmacsha384', 'hmacsha512']
    SYMMETRIC_KEY_LENGTHS = [64, 128, 192, 256]

    ASYMMETRIC_KEY_GENERATION = "ASYMMETRIC_KEY_GENERATION"
    ASYMMETRIC_ALGORITHMS = ['rsa', 'dsa']
    ASYMMETRIC_KEY_LENGTHS = [1024, 2048, 4096]


class KEKMetaDTO(object):
    """Key Encryption Keys (KEKs) in Barbican are intended to represent a
    distinct key that is used to perform encryption on secrets for a particular
    project (tenant).

    ``KEKMetaDTO`` objects are provided to cryptographic backends by Barbican
    to allow plugins to persist metadata related to the project's (tenant's)
    KEK.

    For example, a plugin that interfaces with a Hardware Security Module (HSM)
    may want to use a different encryption key for each tenant. Such a plugin
    could use the ``KEKMetaDTO`` object to save the key ID used for that
    tenant.  Barbican will persist the KEK metadata and ensure that it is
    provided to the plugin every time a request from that same tenant is
    processed.

    .. attribute:: plugin_name

        String attribute used by Barbican to identify the plugin that is bound
        to the KEK metadata.  Plugins should not change this attribute.

    .. attribute:: kek_label

        String attribute used to label the project's (tenant's) KEK by the
        plugin.  The value of this attribute should be meaningful to the
        plugin.  Barbican does not use this value.

    .. attribute:: algorithm

        String attribute used to identify the encryption algorithm used by the
        plugin. e.g. "AES", "3DES", etc.  This value should be meaningful to
        the plugin.  Barbican does not use this value.

    .. attribute:: mode

        String attribute used to identify the algorithm mode used by the
        plugin.  e.g. "CBC", "GCM", etc.  This value should be meaningful to
        the plugin.  Barbican does not use this value.

    .. attribute:: bit_length

        Integer attribute used to identify the bit length of the KEK by the
        plugin.  This value should be meaningful to the plugin.  Barbican does
        not use this value.

    .. attribute:: plugin_meta

       String attribute used to persist any additional metadata that does not
       fit in any other attribute.  The value of this attribute is defined by
       the plugin.  It could be used to store external system references, such
       as Key IDs in an HSM, URIs to an external service, or any other data
       that the plugin deems necessary to persist.  Because this is just a
       plain text field, a plug in may even choose to persist data such as key
       value pairs in a JSON object.
   """

    def __init__(self, kek_datum):
        """kek_datum is typically a barbican.model.models.EncryptedDatum
        instance.  Plugins should never have to create their own instance of
        this class.
        """
        self.kek_label = kek_datum.kek_label
        self.plugin_name = kek_datum.plugin_name
        self.algorithm = kek_datum.algorithm
        self.bit_length = kek_datum.bit_length
        self.mode = kek_datum.mode
        self.plugin_meta = kek_datum.plugin_meta


class GenerateDTO(object):
    """Data Transfer Object used to pass all the necessary data for the plugin
    to generate a secret on behalf of the user.

    .. attribute:: generation_type

        String attribute used to identify the type of secret that should be
        generated. This will be either ``"symmetric"`` or ``"asymmetric"``.

    .. attribute:: algoritm

        String attribute used to specify what type of algorithm the secret will
        be used for.  e.g. ``"AES"`` for a ``"symmetric"`` type, or ``"RSA"``
        for ``"asymmetric"``.

    .. attribute:: mode

        String attribute used to specify what algorithm mode the secret will be
        used for.  e.g. ``"CBC"`` for ``"AES"`` algorithm.

    .. attribute:: bit_length

        Integer attribute used to specify the bit length of the secret.  For
        example, this attribute could specify the key length for an encryption
        key to be used in AES-CBC.
    """

    def __init__(self, algorithm, bit_length, mode, passphrase=None):
        self.algorithm = algorithm
        self.bit_length = bit_length
        self.mode = mode
        self.passphrase = passphrase


class ResponseDTO(object):
    """Data transfer object for secret generation response."""

    def __init__(self, cypher_text, kek_meta_extended=None):
        self.cypher_text = cypher_text
        self.kek_meta_extended = kek_meta_extended


class DecryptDTO(object):
    """Data Transfer Object used to pass all the necessary data for the plugin
    to perform decryption of a secret.

    Currently, this DTO only contains the data produced by the plugin during
    encryption, but in the future this DTO will contain more information, such
    as a transport key for secret wrapping back to the client.

    .. attribute:: encrypted

        The data that was produced by the plugin during encryption.  For some
        plugins this will be the actual bytes that need to be decrypted to
        produce the secret.  In other implementations, this may just be a
        reference to some external system that can produce the unencrypted
        secret.
    """

    def __init__(self, encrypted):
        self.encrypted = encrypted


class EncryptDTO(object):
    """Data Transfer Object used to pass all the necessary data for the plugin
    to perform encryption of a secret.

    Currently, this DTO only contains the raw bytes to be encrypted by the
    plugin, but in the future this may contain more information.

    .. attribute:: unencrypted

        The secret data in Bytes to be encrypted by the plugin.
    """

    def __init__(self, unencrypted):
        self.unencrypted = unencrypted


def indicate_bind_completed(kek_meta_dto, kek_datum):
    """Updates the supplied kek_datum instance per the contents of the supplied
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


@six.add_metaclass(abc.ABCMeta)
class CryptoPluginBase(object):
    """Base class for all Crypto plugins.  Implementations of this abstract
    base class will be used by Barbican to perform cryptographic operations on
    secrets.

    Barbican requests operations by invoking the methods on an instance of the
    implementing class.  Barbican's plugin manager handles the life-cycle of
    the Data Transfer Objects (DTOs) that are passed into these methods, and
    persist the data that is assigned to these DTOs by the plugin.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encrypt(self, encrypt_dto, kek_meta_dto, keystone_id):
        """This method will be called by Barbican when requesting an encryption
        operation on a secret on behalf of a project (tenant).

        :param encrypt_dto: :class:`EncryptDTO` instance containing the raw
            secret byte data to be encrypted.
        :type encrypt_dto: :class:`EncryptDTO`
        :param kek_meta_dto: :class:`KEKMetaDTO` instance containing
            information about the project's (tenant's) Key Encryption Key (KEK)
            to be used for encryption.  Plugins may assume that binding via
            :meth:`bind_kek_metadata` has already taken place before this
            instance is passed in.
        :type kek_meta_dto: :class:`KEKMetaDTO`
        :param keystone_id: Project (tenant) ID associated with the unencrypted
            data.
        :return: A tuple containing two items ``(ciphertext,
            kek_metadata_extended)``.  In a typical plugin implementation, the
            first item in the tuple should be the ciphertext byte data
            resulting from the encryption of the secret data.  The second item
            is an optional String object to be persisted alongside the
            ciphertext.

            Barbican guarantees that both the ``ciphertext`` and
            ``kek_metadata_extended`` will be persisted and then given back to
            the plugin when requesting a decryption operation.

            It should be noted that Barbican does not require that the data
            returned for the ``ciphertext`` be the actual encrypted
            bytes of the secret data.  The only requirement is that the plugin
            is able to use whatever data it chooses to return in ``ciphertext``
            to produce the secret data during decryption.  This allows more
            complex plugins to make decisions regarding the storage of the
            encrypted data.  For example, the DogTag plugin stores the
            encrypted bytes in an external system and uses Barbican to store an
            identifier to the external system in ``ciphertext``.  During
            decryption, Barbican gives the external identifier back to the
            DogTag plugin, and then the plugin is able to use the identifier to
            retrieve the secret data from the external storage system.

            ``kek_metadata_extended`` takes the idea of Key Encryption Key
            (KEK) metadata further by giving plugins the option to store
            secret-level KEK metadata.  One example of using secret-level KEK
            metadata would be plugins that want to use a unique KEK for every
            secret that is encrypted.  Such a plugin could use
            ``kek_metadata_extended`` to store the Key ID for the KEK used to
            encrypt this particular secret.
        :rtype: tuple
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                keystone_id):
        """Decrypt encrypted_datum in the context of the provided tenant.

        :param decrypt_dto: data transfer object containing the cyphertext
               to be decrypted.
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param kek_meta_extended: Optional per-secret KEK metadata to use for
        decryption.
        :param keystone_id: keystone_id associated with the encrypted datum.
        :returns: str -- unencrypted byte data

        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def bind_kek_metadata(self, kek_meta_dto):
        """Bind a key encryption key (KEK) metadata to the sub-system
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
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_symmetric(self, generate_dto, kek_meta_dto, keystone_id):
        """Generate a new key.

        :param generate_dto: data transfer object for the record
               associated with this generation request.  Some relevant
               parameters can be extracted from this object, including
               bit_length, algorithm and mode
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param keystone_id: keystone_id associated with the data.
        :returns: An object of type ResponseDTO containing encrypted data and
        kek_meta_extended, the former the resultant cypher text, the latter
        being optional per-secret metadata needed to decrypt (over and above
        the per-tenant metadata managed outside of the plugins)
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_asymmetric(self, generate_dto,
                            kek_meta_dto, keystone_id):
        """Create a new asymmetric key.

        :param generate_dto: data transfer object for the record
               associated with this generation request.  Some relevant
               parameters can be extracted from this object, including
               bit_length, algorithm and passphrase
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param keystone_id: keystone_id associated with the data.
        :returns: A tuple containing  objects for private_key, public_key and
        optionally one for passphrase. The objects will be of type ResponseDTO.
        Each object containing encrypted data and kek_meta_extended, the former
        the resultant cypher text, the latter being optional per-secret
        metadata needed to decrypt (over and above the per-tenant metadata
        managed outside of the plugins)
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def supports(self, type_enum, algorithm=None, bit_length=None,
                 mode=None):
        """Used to determine if the plugin supports the requested operation.

        :param type_enum: Enumeration from PluginSupportsType class
        :param algorithm: String algorithm name if needed
        """
        raise NotImplementedError  # pragma: no cover


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

    def encrypt(self, encrypt_dto, kek_meta_dto, keystone_id):
        unencrypted = encrypt_dto.unencrypted
        if not isinstance(unencrypted, str):
            raise ValueError('Unencrypted data must be a byte type, '
                             'but was {0}'.format(type(unencrypted)))
        padded_data = self._pad(unencrypted)
        iv = Random.get_random_bytes(self.block_size)
        encryptor = AES.new(self.kek, AES.MODE_CBC, iv)

        cyphertext = iv + encryptor.encrypt(padded_data)

        return ResponseDTO(cyphertext, None)

    def decrypt(self, encrypted_dto, kek_meta_dto, kek_meta_extended,
                keystone_id):
        encrypted = encrypted_dto.encrypted
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

    def generate_symmetric(self, generate_dto, kek_meta_dto, keystone_id):
        byte_length = int(generate_dto.bit_length) / 8
        unencrypted = Random.get_random_bytes(byte_length)

        return self.encrypt(EncryptDTO(unencrypted),
                            kek_meta_dto,
                            keystone_id)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, keystone_id):
        """Generate asymmetric keys based on below rule
        - RSA, with passphrase (supported)
        - RSA, without passphrase (supported)
        - DSA, without passphrase (supported)
        - DSA, with passphrase (not supported)

        Note: PyCrypto is not capable of serializing DSA
        keys and DER formated keys. Such keys will be
        serialized to Base64 PEM to store in DB.

        TODO (atiwari/reaperhulk): PyCrypto is not capable to serialize
        DSA keys and DER formated keys, later we need to pick better
        crypto lib.
        """
        if generate_dto.algorithm is None\
                or generate_dto.algorithm.lower() == 'rsa':
            private_key = RSA.generate(
                generate_dto.bit_length, None, None, 65537)
        elif generate_dto.algorithm.lower() == 'dsa':
            private_key = DSA.generate(generate_dto.bit_length, None, None)

        public_key = private_key.publickey()

        # Note (atiwari): key wrapping format PEM only supported
        if generate_dto.algorithm.lower() == 'rsa':
            public_key, private_key = self._wrap_key(public_key, private_key,
                                                     generate_dto.passphrase)
        if generate_dto.algorithm.lower() == 'dsa':
            if generate_dto.passphrase:
                raise ValueError('Passphrase not supported for DSA key')
            public_key, private_key = self._serialize_dsa_key(public_key,
                                                              private_key)
        private_dto = self.encrypt(EncryptDTO(private_key),
                                   kek_meta_dto,
                                   keystone_id)

        public_dto = self.encrypt(EncryptDTO(public_key),
                                  kek_meta_dto,
                                  keystone_id)

        passphrase_dto = None
        if generate_dto.passphrase:
            passphrase_dto = self.encrypt(EncryptDTO(generate_dto.passphrase),
                                          kek_meta_dto,
                                          keystone_id)

        return private_dto, public_dto, passphrase_dto

    def supports(self, type_enum, algorithm=None, bit_length=None,
                 mode=None):
        if type_enum == PluginSupportTypes.ENCRYPT_DECRYPT:
            return True

        if type_enum == PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length)
        elif type_enum == PluginSupportTypes.ASYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length)
        else:
            return False

    def _wrap_key(self, public_key, private_key,
                  passphrase):
        pkcs = 8
        key_wrap_format = 'PEM'

        private_key = private_key.exportKey(key_wrap_format, passphrase, pkcs)
        public_key = public_key.exportKey()

        return (public_key, private_key)

    def _serialize_dsa_key(self, public_key, private_key):

        pub_seq = asn1.DerSequence()
        pub_seq[:] = [0, public_key.p, public_key.q,
                      public_key.g, public_key.y]
        public_key = "-----BEGIN DSA PUBLIC KEY-----\n%s"\
            "-----END DSA PUBLIC KEY-----" % pub_seq.encode().encode("base64")

        prv_seq = asn1.DerSequence()
        prv_seq[:] = [0, private_key.p, private_key.q,
                      private_key.g, private_key.y, private_key.x]
        private_key = "-----BEGIN DSA PRIVATE KEY-----\n%s"\
            "-----END DSA PRIVATE KEY-----" % prv_seq.encode().encode("base64")

        return (public_key, private_key)

    def _is_algorithm_supported(self, algorithm=None, bit_length=None):
        """check if algorithm and bit_length combination is supported."""
        if algorithm is None or bit_length is None:
            return False

        if algorithm.lower() in PluginSupportTypes.SYMMETRIC_ALGORITHMS \
                and bit_length in PluginSupportTypes.SYMMETRIC_KEY_LENGTHS:
            return True
        elif algorithm.lower() in PluginSupportTypes.ASYMMETRIC_ALGORITHMS \
                and bit_length in PluginSupportTypes.ASYMMETRIC_KEY_LENGTHS:
            return True
        else:
            return False
