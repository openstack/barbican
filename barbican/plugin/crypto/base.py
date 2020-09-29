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

from barbican.common import exception
from barbican import i18n as u


class CryptoPluginNotFound(exception.BarbicanException):
    """Raised when no plugins are installed."""
    message = u._("Crypto plugin not found.")


class CryptoKEKBindingException(exception.BarbicanException):
    """Raised when the bind_kek_metadata method from a plugin returns None."""
    def __init__(self, plugin_name=u._('Unknown')):
        super(CryptoKEKBindingException, self).__init__(
            u._('Failed to bind kek metadata for '
                'plugin: {name}').format(name=plugin_name)
        )
        self.plugin_name = plugin_name


class CryptoPrivateKeyFailureException(exception.BarbicanException):
    """Raised when could not generate private key."""
    def __init__(self):
        super(CryptoPrivateKeyFailureException, self).__init__(
            u._('Could not generate private key')
        )


class CryptoPluginUnsupportedOperation(exception.BarbicanException):
    """Raised when no crypto plugins support the operation."""
    def __init__(self, operation):
        message = (
            u._('Could not find an enabled crypto plugin backend '
                'that supports the requested operation: {operation}')
            .format(operation=operation))
        super(CryptoPluginUnsupportedOperation, self).__init__(message)


# TODO(john-wood-w) Need to harmonize these lower-level constants with the
#  higher level constants in secret_store.py.
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
    """Key Encryption Key Meta DTO

    Key Encryption Keys (KEKs) in Barbican are intended to represent a
    distinct key that is used to perform encryption on secrets for a particular
    project.

    ``KEKMetaDTO`` objects are provided to cryptographic backends by Barbican
    to allow plugins to persist metadata related to the project's KEK.

    For example, a plugin that interfaces with a Hardware Security Module (HSM)
    may want to use a different encryption key for each project. Such a plugin
    could use the ``KEKMetaDTO`` object to save the key ID used for that
    project.  Barbican will persist the KEK metadata and ensure that it is
    provided to the plugin every time a request from that same project is
    processed.

    .. attribute:: plugin_name

        String attribute used by Barbican to identify the plugin that is bound
        to the KEK metadata.  Plugins should not change this attribute.

    .. attribute:: kek_label

        String attribute used to label the project's KEK by the plugin.
        The value of this attribute should be meaningful to the plugin.
        Barbican does not use this value.

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
        """Plugins should not have to create their own instance of this class.

        kek_datum is typically a barbican.model.models.KEKDatum instance.
        """
        self.kek_label = kek_datum.kek_label
        self.plugin_name = kek_datum.plugin_name
        self.algorithm = kek_datum.algorithm
        self.bit_length = kek_datum.bit_length
        self.mode = kek_datum.mode
        self.plugin_meta = kek_datum.plugin_meta


class GenerateDTO(object):
    """Secret Generation DTO

    Data Transfer Object used to pass all the necessary data for the plugin
    to generate a secret on behalf of the user.

    .. attribute:: generation_type

        String attribute used to identify the type of secret that should be
        generated. This will be either ``"symmetric"`` or ``"asymmetric"``.

    .. attribute:: algorithm

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
    """Data transfer object for secret generation response.

    Barbican guarantees that both the ``cypher_text`` and
    ``kek_metadata_extended`` will be persisted and then given back to
    the plugin when requesting a decryption operation.

    ``kek_metadata_extended`` takes the idea of Key Encryption Key
    (KEK) metadata further by giving plugins the option to store
    secret-level KEK metadata.  One example of using secret-level KEK
    metadata would be plugins that want to use a unique KEK for every
    secret that is encrypted.  Such a plugin could use
    ``kek_metadata_extended`` to store the Key ID for the KEK used to
    encrypt this particular secret.

    :param cypher_text: Byte data resulting from the encryption of the
        secret data.
    :param kek_meta_extended: Optional String object to be persisted alongside
        the cyphertext.
    """
    def __init__(self, cypher_text, kek_meta_extended=None):
        self.cypher_text = cypher_text
        self.kek_meta_extended = kek_meta_extended


class DecryptDTO(object):
    """Secret Decryption DTO

    Data Transfer Object used to pass all the necessary data for the plugin
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
    """Secret Encryption DTO

    Data Transfer Object used to pass all the necessary data for the plugin
    to perform encryption of a secret.

    Currently, this DTO only contains the raw bytes to be encrypted by the
    plugin, but in the future this may contain more information.

    .. attribute:: unencrypted

        The secret data in Bytes to be encrypted by the plugin.
    """

    def __init__(self, unencrypted):
        self.unencrypted = unencrypted


class CryptoPluginBase(object, metaclass=abc.ABCMeta):
    """Base class for all Crypto plugins.

    Barbican requests operations by invoking the methods on an instance of the
    implementing class.  Barbican's plugin manager handles the life-cycle of
    the Data Transfer Objects (DTOs) that are passed into these methods, and
    persist the data that is assigned to these DTOs by the plugin.
    """

    @abc.abstractmethod
    def get_plugin_name(self):
        """Gets user friendly plugin name.

        This plugin name is expected to be read from config file.
        There will be a default defined for plugin name which can be customized
        in specific deployment if needed.

        This name needs to be unique across a deployment.
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        """Encryption handler function

        This method will be called by Barbican when requesting an encryption
        operation on a secret on behalf of a project.

        :param encrypt_dto: :class:`EncryptDTO` instance containing the raw
            secret byte data to be encrypted.
        :type encrypt_dto: :class:`EncryptDTO`
        :param kek_meta_dto: :class:`KEKMetaDTO` instance containing
            information about the project's Key Encryption Key (KEK) to be
            used for encryption.  Plugins may assume that binding via
            :meth:`bind_kek_metadata` has already taken place before this
            instance is passed in.
        :type kek_meta_dto: :class:`KEKMetaDTO`
        :param project_id: Project ID associated with the unencrypted data.
        :return: A response DTO containing the cyphertext and KEK information.
        :rtype: :class:`ResponseDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        """Decrypt encrypted_datum in the context of the provided project.

        :param decrypt_dto: data transfer object containing the cyphertext
               to be decrypted.
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param kek_meta_extended: Optional per-secret KEK metadata to use for
            decryption.
        :param project_id: Project ID associated with the encrypted datum.
        :returns: str -- unencrypted byte data

        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def bind_kek_metadata(self, kek_meta_dto):
        """Key Encryption Key Metadata binding function

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
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        """Generate a new key.

        :param generate_dto: data transfer object for the record
               associated with this generation request.  Some relevant
               parameters can be extracted from this object, including
               bit_length, algorithm and mode
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param project_id: Project ID associated with the data.
        :returns: An object of type ResponseDTO containing encrypted data and
            kek_meta_extended, the former the resultant cypher text, the latter
            being optional per-secret metadata needed to decrypt (over and
            above the per-project metadata managed outside of the plugins)
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_asymmetric(self, generate_dto, kek_meta_dto, project_id):
        """Create a new asymmetric key.

        :param generate_dto: data transfer object for the record
               associated with this generation request.  Some relevant
               parameters can be extracted from this object, including
               bit_length, algorithm and passphrase
        :param kek_meta_dto: Key encryption key metadata to use for decryption
        :param project_id: Project ID associated with the data.
        :returns: A tuple containing  objects for private_key, public_key and
            optionally one for passphrase. The objects will be of type
            ResponseDTO.
            Each object containing encrypted data and kek_meta_extended, the
            former the resultant cypher text, the latter being optional
            per-secret metadata needed to decrypt (over and above the
            per-project metadata managed outside of the plugins)
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def supports(self, type_enum, algorithm=None, bit_length=None, mode=None):
        """Used to determine if the plugin supports the requested operation.

        :param type_enum: Enumeration from PluginSupportsType class
        :param algorithm: String algorithm name if needed
        """
        raise NotImplementedError  # pragma: no cover
