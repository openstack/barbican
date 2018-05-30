# Copyright (c) 2014 Johns Hopkins University Applied Physics Laboratory
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

"""
An implementation of the SecretStore that uses the KMIP backend.
"""

import base64
import os
import ssl
import stat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from kmip.core import enums
from kmip.core.factories import credentials
from kmip.pie import client
from kmip.pie import objects

from oslo_config import cfg
from oslo_log import log

from barbican.common import config
from barbican.common import exception
from barbican import i18n as u  # noqa
from barbican.plugin.interface import secret_store as ss
from barbican.plugin.util import translations

LOG = log.getLogger(__name__)

CONF = config.new_config()

kmip_opt_group = cfg.OptGroup(name='kmip_plugin', title='KMIP Plugin')
kmip_opts = [
    cfg.StrOpt('username',
               help=u._('Username for authenticating with KMIP server')
               ),
    cfg.StrOpt('password',
               help=u._('Password for authenticating with KMIP server'),
               secret=True,
               ),
    cfg.StrOpt('host',
               default='localhost',
               help=u._('Address of the KMIP server')
               ),
    cfg.PortOpt('port',
                default=5696,
                help=u._('Port for the KMIP server'),
                ),
    cfg.StrOpt('ssl_version',
               default='PROTOCOL_TLSv1_2',
               help=u._('SSL version, maps to the module ssl\'s constants'),
               ),
    cfg.StrOpt('ca_certs',
               help=u._('File path to concatenated "certification authority" '
                        'certificates'),
               ),
    cfg.StrOpt('certfile',
               help=u._('File path to local client certificate'),
               ),
    cfg.StrOpt('keyfile',
               help=u._('File path to local client certificate keyfile'),
               ),
    cfg.BoolOpt('pkcs1_only',
                default=False,
                help=u._('Only support PKCS#1 encoding of asymmetric keys'),
                ),
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='KMIP HSM'),
]
CONF.register_group(kmip_opt_group)
CONF.register_opts(kmip_opts, group=kmip_opt_group)
config.parse_args(CONF)


def list_opts():
    yield kmip_opt_group, kmip_opts


attribute_debug_msg = "Created attribute type %s with value %s"


def convert_pem_to_der(pem_pkcs1):
    # cryptography adds an extra '\n' to end of PEM file
    # added if statement so if future version removes extra \n tests will not
    # break
    if pem_pkcs1.endswith(b'\n'):
        pem_pkcs1 = pem_pkcs1[:-1]
    # neither PyCrypto or cryptography support export in DER format with PKCS1
    # encoding so doing by hand
    der_pkcs1_b64 = b''.join(pem_pkcs1.split(b'\n')[1:-1])
    der_pkcs1 = base64.b64decode(der_pkcs1_b64)
    return der_pkcs1


def get_public_key_der_pkcs1(pem):
    """Converts PEM public key to DER PKCS1"""
    rsa_public = serialization.load_pem_public_key(
        pem,
        backend=default_backend())
    pem_pkcs1 = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    return convert_pem_to_der(pem_pkcs1)


def get_private_key_der_pkcs1(pem):
    """Converts PEM private key to DER PKCS1"""
    rsa_private = serialization.load_pem_private_key(
        pem,
        None,
        backend=default_backend())
    pem_pkcs1 = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    return convert_pem_to_der(pem_pkcs1)


class KMIPSecretStoreError(exception.BarbicanException):
    def __init__(self, message):
        super(KMIPSecretStoreError, self).__init__(message)


class KMIPSecretStoreActionNotSupported(exception.BarbicanHTTPException):
    """Raised if no plugins are found that support the requested operation."""

    client_message = u._("KMIP plugin action not support.")
    status_code = 400

    def __init__(self, message):
        self.message = message
        super(KMIPSecretStoreActionNotSupported, self).__init__()


class KMIPSecretStore(ss.SecretStoreBase):

    KEY_UUID = "key_uuid"
    VALID_BIT_LENGTHS = "valid_bit_lengths"
    KMIP_ALGORITHM_ENUM = "kmip_algorithm_enum"

    def __init__(self, conf=CONF):
        """Initializes KMIPSecretStore

        Creates a dictionary of mappings between SecretStore enum values
        and pyKMIP enum values. Initializes the KMIP client with credentials
        needed to connect to the KMIP server.
        """
        super(KMIPSecretStore, self).__init__()
        self.valid_alg_dict = {
            ss.KeyAlgorithm.AES: {
                KMIPSecretStore.VALID_BIT_LENGTHS: [128, 192, 256],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.AES},
            ss.KeyAlgorithm.DES: {
                KMIPSecretStore.VALID_BIT_LENGTHS: [56],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.DES},
            ss.KeyAlgorithm.DESEDE: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [56, 64, 112, 128, 168, 192],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.TRIPLE_DES},
            ss.KeyAlgorithm.DSA: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [1024, 2048, 3072],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.DSA},
            ss.KeyAlgorithm.HMACSHA1: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.HMAC_SHA1},
            ss.KeyAlgorithm.HMACSHA256: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.HMAC_SHA256},
            ss.KeyAlgorithm.HMACSHA384: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.HMAC_SHA384},
            ss.KeyAlgorithm.HMACSHA512: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.HMAC_SHA512},
            ss.KeyAlgorithm.RSA: {
                KMIPSecretStore.VALID_BIT_LENGTHS:
                [1024, 2048, 3072, 4096],
                KMIPSecretStore.KMIP_ALGORITHM_ENUM:
                enums.CryptographicAlgorithm.RSA},
        }
        self.pkcs1_only = conf.kmip_plugin.pkcs1_only
        if self.pkcs1_only:
            LOG.debug("KMIP secret store only supports PKCS#1")
            del self.valid_alg_dict[ss.KeyAlgorithm.DSA]
        self.kmip_barbican_alg_map = {
            enums.CryptographicAlgorithm.AES: ss.KeyAlgorithm.AES,
            enums.CryptographicAlgorithm.DES: ss.KeyAlgorithm.DES,
            enums.CryptographicAlgorithm.TRIPLE_DES: ss.KeyAlgorithm.DESEDE,
            enums.CryptographicAlgorithm.DSA: ss.KeyAlgorithm.DSA,
            enums.CryptographicAlgorithm.HMAC_SHA1: ss.KeyAlgorithm.HMACSHA1,
            enums.CryptographicAlgorithm.HMAC_SHA256:
                ss.KeyAlgorithm.HMACSHA256,
            enums.CryptographicAlgorithm.HMAC_SHA384:
                ss.KeyAlgorithm.HMACSHA384,
            enums.CryptographicAlgorithm.HMAC_SHA512:
                ss.KeyAlgorithm.HMACSHA512,
            enums.CryptographicAlgorithm.RSA: ss.KeyAlgorithm.RSA
        }

        self.plugin_name = conf.kmip_plugin.plugin_name

        if conf.kmip_plugin.keyfile is not None:
            self._validate_keyfile_permissions(conf.kmip_plugin.keyfile)

        if (conf.kmip_plugin.username is None) and (
                conf.kmip_plugin.password is None):
            self.credential = None
        else:
            credential_type = enums.CredentialType.USERNAME_AND_PASSWORD
            credential_value = {'Username': conf.kmip_plugin.username,
                                'Password': conf.kmip_plugin.password}
            self.credential = (
                credentials.CredentialFactory().create_credential(
                    credential_type,
                    credential_value))

        config = conf.kmip_plugin

        if not getattr(ssl, config.ssl_version, None):
            LOG.error("The configured SSL version (%s) is not available"
                      " on the system.", config.ssl_version)

        self.client = client.ProxyKmipClient(
            hostname=config.host,
            port=config.port,
            cert=config.certfile,
            key=config.keyfile,
            ca=config.ca_certs,
            ssl_version=config.ssl_version,
            username=config.username,
            password=config.password)

    def get_plugin_name(self):
        return self.plugin_name

    def generate_symmetric_key(self, key_spec):
        """Generate a symmetric key.

        Creates KMIP attribute objects based on the given KeySpec to send to
        the server.

        :param key_spec: KeySpec with symmetric algorithm and bit_length
        :returns: dictionary holding key_id returned by server
        :raises: SecretGeneralException, SecretAlgorithmNotSupportedException
        """
        LOG.debug("Starting symmetric key generation with KMIP plugin")
        if not self.generate_supports(key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                key_spec.alg)

        if key_spec.alg.lower() not in ss.KeyAlgorithm.SYMMETRIC_ALGORITHMS:
            raise KMIPSecretStoreError(
                u._("An unsupported algorithm {algorithm} was passed to the "
                    "'generate_symmetric_key' method").format(
                        algorithm=key_spec.alg))

        algorithm = self._get_kmip_algorithm(key_spec.alg.lower())
        try:
            with self.client:
                LOG.debug("Opened connection to KMIP client for secret "
                          "generation")
                uuid = self.client.create(algorithm, key_spec.bit_length)
                LOG.debug("SUCCESS: Symmetric key generated with "
                          "uuid: %s", uuid)
                return {KMIPSecretStore.KEY_UUID: uuid}
        except Exception as e:
            LOG.exception("Error opening or writing to client")
            raise ss.SecretGeneralException(e)

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key pair.

        Creates KMIP attribute objects based on the given KeySpec to send to
        the server. The KMIP Secret Store currently does not support
        protecting the private key with a passphrase.

        :param key_spec: KeySpec with asymmetric algorithm and bit_length
        :returns: AsymmetricKeyMetadataDTO with the key UUIDs
        :raises: SecretGeneralException, SecretAlgorithmNotSupportedException
                 KMIPSecretStoreActionNotSupported
        """
        LOG.debug("Starting asymmetric key generation with KMIP plugin")
        if not self.generate_supports(key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                key_spec.alg)

        if key_spec.alg.lower() not in ss.KeyAlgorithm.ASYMMETRIC_ALGORITHMS:
            raise ss.SecretAlgorithmNotSupportedException(key_spec.alg)

        if key_spec.passphrase:
            raise KMIPSecretStoreActionNotSupported(
                u._('KMIP plugin does not currently support protecting the '
                    'private key with a passphrase'))

        algorithm = self._get_kmip_algorithm(key_spec.alg.lower())
        length = key_spec.bit_length

        try:
            with self.client:
                LOG.debug("Opened connection to KMIP client for "
                          "asymmetric secret generation")
                public_uuid, private_uuid = self.client.create_key_pair(
                    algorithm, length)
                LOG.debug("SUCCESS: Asymmetric key pair generated with "
                          "public key uuid: %(public_uuid)s and "
                          "private key uuid: %(private_uuid)s" %
                          {'public_uuid': public_uuid,
                           'private_uuid': private_uuid})
                private_key_metadata = {KMIPSecretStore.KEY_UUID: private_uuid}
                public_key_metadata = {KMIPSecretStore.KEY_UUID: public_uuid}
                passphrase_metadata = None
                return ss.AsymmetricKeyMetadataDTO(private_key_metadata,
                                                   public_key_metadata,
                                                   passphrase_metadata)
        except Exception as e:
            LOG.exception("Error opening or writing to client")
            raise ss.SecretGeneralException(e)

    def store_secret(self, secret_dto):
        """Stores a secret

        To store a secret in KMIP, the attributes must be known.

        :param secret_dto: SecretDTO of the secret to be stored
        :returns: Dictionary holding the key_uuid assigned by KMIP
        :raises: SecretGeneralException, SecretAlgorithmNotSupportedException
        """
        LOG.debug("Starting secret storage with KMIP plugin")
        if not self.store_secret_supports(secret_dto.key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                secret_dto.key_spec.alg)

        secret_type = secret_dto.type
        object_type, key_format_type = (
            self._map_type_ss_to_kmip(secret_type))
        if object_type is None:
            raise KMIPSecretStoreError(
                u._('Secret object type {object_type} is '
                    'not supported').format(object_type=object_type))

        secret = self._get_kmip_secret(secret_dto)

        try:
            with self.client:
                LOG.debug("Opened connection to KMIP client")
                uuid = self.client.register(secret)
                LOG.debug("SUCCESS: Key stored with uuid: %s", uuid)
                return {KMIPSecretStore.KEY_UUID: uuid}
        except Exception as e:
            LOG.exception("Error opening or writing to client")
            raise ss.SecretGeneralException(e)

    def get_secret(self, secret_type, secret_metadata):
        """Gets a secret

        :param secret_type: secret type
        :param secret_metadata: Dictionary of key metadata, requires:
        {'key_uuid': <uuid of key>}
        :returns: SecretDTO of the retrieved Secret
        :raises: SecretGeneralException
        """
        LOG.debug("Starting secret retrieval with KMIP plugin")
        uuid = str(secret_metadata[KMIPSecretStore.KEY_UUID])
        try:
            with self.client:
                LOG.debug("Opened connection to KMIP client for secret "
                          "retrieval")
                managed_object = self.client.get(uuid)
                return self._get_barbican_secret(managed_object, secret_type)
        except Exception as e:
            LOG.exception("Error opening or writing to client")
            raise ss.SecretGeneralException(e)

    def generate_supports(self, key_spec):
        """Key generation supported?

        Specifies whether the plugin supports key generation with the
        given key_spec. Currently, asymmetric key pair generation does not
        support encrypting the private key with a passphrase.

        Checks both the algorithm and the bit length. Only symmetric
        algorithms are currently supported.
        :param key_spec: KeySpec for secret to be generates
        :returns: boolean indicating if secret can be generated
        """
        alg_dict_entry = self.valid_alg_dict.get(key_spec.alg.lower())
        if alg_dict_entry:
            valid_bit_lengths = alg_dict_entry.get(
                KMIPSecretStore.VALID_BIT_LENGTHS)
            if (key_spec.bit_length in valid_bit_lengths
                    or not valid_bit_lengths):
                return True
        return False

    def delete_secret(self, secret_metadata):
        """Deletes the secret whose metadata is included in the dictionary.

        Returns nothing if successful, raises an exception if an error occurs
        :param secret_metadata: Dictionary of key metadata, requires:
        {'key_uuid': <uuid of key>}
        :raises: SecretGeneralException
        """
        LOG.debug("Starting secret deletion with KMIP plugin")
        uuid = str(secret_metadata[KMIPSecretStore.KEY_UUID])
        try:
            with self.client:
                LOG.debug("Opened connection to KMIP client")
                self.client.destroy(uuid)
        except Exception as e:
            LOG.exception("Error opening or writing to client")
            raise ss.SecretGeneralException(e)

    def store_secret_supports(self, key_spec):
        """Key storage supported?

        Specifies whether the plugin supports storage of the secret given
        the attributes included in the KeySpec.

        For now this always returns true if the key spec's algorithm and bit
        length are not specified. The secret type may need to be added in the
        future. This must always return true if the algorithm and bit length
        are not specified because some secret types, like certificate, do not
        require algorithm and bit length, so true must always be returned for
        those cases.
        :param key_spec: KeySpec of secret to be stored
        :returns: boolean indicating if secret can be stored
        """
        if key_spec.alg is not None and key_spec.bit_length is not None:
            return self.generate_supports(key_spec)
        else:
            return True

    def _get_kmip_secret(self, secret_dto):
        """Builds a KMIP object from a SecretDTO

        This is needed for register calls. The Barbican object needs to be
        converted to KMIP object before it can be stored

        :param secret_dto: SecretDTO of secret to be stored
        :returns: KMIP object
        """
        secret_type = secret_dto.type
        key_spec = secret_dto.key_spec
        object_type, key_format_type = (
            self._map_type_ss_to_kmip(secret_type))

        normalized_secret = self._normalize_secret(secret_dto.secret,
                                                   secret_type)
        kmip_object = None
        if object_type == enums.ObjectType.CERTIFICATE:
            kmip_object = objects.X509Certificate(normalized_secret)
        elif object_type == enums.ObjectType.OPAQUE_DATA:
            opaque_type = enums.OpaqueDataType.NONE
            kmip_object = objects.OpaqueObject(normalized_secret,
                                               opaque_type)
        elif object_type == enums.ObjectType.PRIVATE_KEY:
            algorithm = self._get_kmip_algorithm(key_spec.alg)
            length = key_spec.bit_length
            format_type = enums.KeyFormatType.PKCS_8
            kmip_object = objects.PrivateKey(
                algorithm, length, normalized_secret, format_type)
        elif object_type == enums.ObjectType.PUBLIC_KEY:
            algorithm = self._get_kmip_algorithm(key_spec.alg)
            length = key_spec.bit_length
            format_type = enums.KeyFormatType.X_509
            kmip_object = objects.PublicKey(
                algorithm, length, normalized_secret, format_type)
        elif object_type == enums.ObjectType.SYMMETRIC_KEY:
            algorithm = self._get_kmip_algorithm(key_spec.alg)
            length = key_spec.bit_length
            kmip_object = objects.SymmetricKey(algorithm, length,
                                               normalized_secret)
        elif object_type == enums.ObjectType.SECRET_DATA:
            data_type = enums.SecretDataType.PASSWORD
            kmip_object = objects.SecretData(normalized_secret, data_type)

        return kmip_object

    def _get_kmip_algorithm(self, ss_algorithm):
        alg_entry = self.valid_alg_dict.get(ss_algorithm)
        return alg_entry.get(KMIPSecretStore.KMIP_ALGORITHM_ENUM)

    def _get_barbican_secret(self, managed_object, secret_type):
        object_type = managed_object.object_type
        secret = managed_object.value
        if (object_type == enums.ObjectType.SYMMETRIC_KEY or
                object_type == enums.ObjectType.PRIVATE_KEY or
                object_type == enums.ObjectType.PUBLIC_KEY):
            algorithm = self.kmip_barbican_alg_map[
                managed_object.cryptographic_algorithm]
            length = managed_object.cryptographic_length
            key_spec = ss.KeySpec(algorithm, length)
        else:
            key_spec = ss.KeySpec()

        secret = self._denormalize_secret(secret, secret_type)
        secret_dto = ss.SecretDTO(
            secret_type,
            secret,
            key_spec,
            content_type=None,
            transport_key=None)
        return secret_dto

    def _map_type_ss_to_kmip(self, object_type):
        """Map SecretType to KMIP type enum

        Returns None if the type is not supported.
        :param object_type: SecretType enum value
        :returns: KMIP type enums if supported, None if not supported
        """
        if object_type == ss.SecretType.SYMMETRIC:
            return enums.ObjectType.SYMMETRIC_KEY, enums.KeyFormatType.RAW
        elif object_type == ss.SecretType.PRIVATE:
            if self.pkcs1_only:
                return enums.ObjectType.PRIVATE_KEY, enums.KeyFormatType.PKCS_1
            else:
                return enums.ObjectType.PRIVATE_KEY, enums.KeyFormatType.PKCS_8
        elif object_type == ss.SecretType.PUBLIC:
            if self.pkcs1_only:
                return enums.ObjectType.PUBLIC_KEY, enums.KeyFormatType.PKCS_1
            else:
                return enums.ObjectType.PUBLIC_KEY, enums.KeyFormatType.X_509
        elif object_type == ss.SecretType.CERTIFICATE:
            return enums.ObjectType.CERTIFICATE, enums.KeyFormatType.X_509
        elif object_type == ss.SecretType.PASSPHRASE:
            return enums.ObjectType.SECRET_DATA, enums.KeyFormatType.RAW
        elif object_type == ss.SecretType.OPAQUE:
            return enums.ObjectType.OPAQUE_DATA, enums.KeyFormatType.RAW
        else:
            return None, None

    def _raise_secret_general_exception(self, result):
        msg = u._(
            "Status: {status}, Reason: {reason}, "
            "Message: {message}"
        ).format(
            status=result.result_status,
            reason=result.result_reason,
            message=result.result_message
        )
        LOG.error("ERROR from KMIP server: %s", msg)
        raise ss.SecretGeneralException(msg)

    def _validate_keyfile_permissions(self, path):
        """Check that file has permissions appropriate for a sensitive key

        Key files are extremely sensitive, they should be owned by the user
        who they relate to. They should be readable only (to avoid accidental
        changes). They should not be readable or writable by any other user.

        :raises: KMIPSecretStoreError
        """
        expected = (stat.S_IRUSR | stat.S_IFREG)  # 0o100400
        st = os.stat(path)
        if st.st_mode != expected:
            raise KMIPSecretStoreError(
                u._('Bad key file permissions found, expected 400 '
                    'for path: {file_path}').format(file_path=path)
            )

    def _normalize_secret(self, secret, secret_type):
        """Normalizes secret for use by KMIP plugin"""
        data = base64.b64decode(secret)
        if (self.pkcs1_only and
                secret_type in [ss.SecretType.PUBLIC, ss.SecretType.PRIVATE]):
            if secret_type == ss.SecretType.PUBLIC:
                data = get_public_key_der_pkcs1(data)
            elif secret_type == ss.SecretType.PRIVATE:
                data = get_private_key_der_pkcs1(data)
        elif secret_type in [ss.SecretType.PUBLIC,
                             ss.SecretType.PRIVATE,
                             ss.SecretType.CERTIFICATE]:
            data = translations.convert_pem_to_der(data, secret_type)
        return data

    def _denormalize_secret(self, secret, secret_type):
        """Converts secret back to the format expected by Barbican core"""
        data = secret
        if secret_type in [ss.SecretType.PUBLIC,
                           ss.SecretType.PRIVATE,
                           ss.SecretType.CERTIFICATE]:
            data = translations.convert_der_to_pem(data, secret_type)
        return base64.b64encode(data)
