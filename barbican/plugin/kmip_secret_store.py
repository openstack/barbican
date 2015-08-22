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
import stat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core import enums
from kmip.core.factories import attributes
from kmip.core.factories import credentials
from kmip.core import misc
from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyMaterialStruct
from kmip.core.objects import KeyValue
from kmip.core.objects import TemplateAttribute
from kmip.core.secrets import Certificate
from kmip.core.secrets import OpaqueObject as Opaque
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey
from kmip.core.secrets import SecretData
from kmip.core.secrets import SymmetricKey
from kmip.services import kmip_client

from oslo_config import cfg
from oslo_log import log
import six

from barbican.common import config
from barbican import i18n as u  # noqa
from barbican.plugin.interface import secret_store as ss
from barbican.plugin.util import translations

LOG = log.getLogger(__name__)

CONF = config.new_config()

kmip_opt_group = cfg.OptGroup(name='kmip_plugin', title='KMIP Plugin')
kmip_opts = [
    cfg.StrOpt('username',
               default=None,
               help=u._('Username for authenticating with KMIP server')
               ),
    cfg.StrOpt('password',
               default=None,
               help=u._('Password for authenticating with KMIP server')
               ),
    cfg.StrOpt('host',
               default='localhost',
               help=u._('Address of the KMIP server')
               ),
    cfg.StrOpt('port',
               default='5696',
               help=u._('Port for the KMIP server'),
               ),
    cfg.StrOpt('ssl_version',
               default='PROTOCOL_TLSv1',
               help=u._('SSL version, maps to the module ssl\'s constants'),
               ),
    cfg.StrOpt('ca_certs',
               default=None,
               help=u._('File path to concatenated "certification authority" '
                        'certificates'),
               ),
    cfg.StrOpt('certfile',
               default=None,
               help=u._('File path to local client certificate'),
               ),
    cfg.StrOpt('keyfile',
               default=None,
               help=u._('File path to local client certificate keyfile'),
               ),
    cfg.BoolOpt('pkcs1_only',
                default=False,
                help=u._('Only support PKCS#1 encoding of asymmetric keys'),
                )
]
CONF.register_group(kmip_opt_group)
CONF.register_opts(kmip_opts, group=kmip_opt_group)
config.parse_args(CONF)

attribute_debug_msg = "Created attribute type %s with value %s"


def convert_pem_to_der(pem_pkcs1):
    # cryptography adds an extra '\n' to end of PEM file
    # added if statement so if future version removes extra \n tests will not
    # break
    if pem_pkcs1.endswith('\n'):
        pem_pkcs1 = pem_pkcs1[:-1]
    # neither PyCrypto or cryptography support export in DER format with PKCS1
    # encoding so doing by hand
    der_pkcs1_b64 = ''.join(pem_pkcs1.split('\n')[1:-1])
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


class KMIPSecretStoreError(Exception):
    def __init__(self, what):
        super(KMIPSecretStoreError, self).__init__(what)


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

        if conf.kmip_plugin.keyfile is not None:
            self._validate_keyfile_permissions(conf.kmip_plugin.keyfile)

        if (conf.kmip_plugin.username is None) and (
                conf.kmip_plugin.password is None):
            self.credential = None
        else:
            credential_type = credentials.CredentialType.USERNAME_AND_PASSWORD
            credential_value = {'Username': conf.kmip_plugin.username,
                                'Password': conf.kmip_plugin.password}
            self.credential = (
                credentials.CredentialFactory().create_credential(
                    credential_type,
                    credential_value))

        self.client = kmip_client.KMIPProxy(
            host=conf.kmip_plugin.host,
            port=int(conf.kmip_plugin.port),
            ssl_version=conf.kmip_plugin.ssl_version,
            ca_certs=conf.kmip_plugin.ca_certs,
            certfile=conf.kmip_plugin.certfile,
            keyfile=conf.kmip_plugin.keyfile,
            username=conf.kmip_plugin.username,
            password=conf.kmip_plugin.password)

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

        object_type = enums.ObjectType.SYMMETRIC_KEY

        algorithm = self._create_cryptographic_algorithm_attribute(
            key_spec.alg)

        usage_mask = self._create_usage_mask_attribute(object_type)

        length = self._create_cryptographic_length_attribute(
            key_spec.bit_length)

        attribute_list = [algorithm, usage_mask, length]
        template_attribute = TemplateAttribute(
            attributes=attribute_list)

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret " +
                      "generation")
            result = self.client.create(object_type=object_type,
                                        template_attribute=template_attribute,
                                        credential=self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                LOG.debug("SUCCESS: Symmetric key generated with "
                          "uuid: %s", result.uuid.value)
                return {KMIPSecretStore.KEY_UUID: result.uuid.value}
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for secret " +
                      "generation")

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key pair.

        Creates KMIP attribute objects based on the given KeySpec to send to
        the server. The KMIP Secret Store currently does not support
        protecting the private key with a passphrase.

        :param key_spec: KeySpec with asymmetric algorithm and bit_length
        :returns: AsymmetricKeyMetadataDTO with the key UUIDs
        :raises: SecretGeneralException, SecretAlgorithmNotSupportedException
        """
        LOG.debug("Starting asymmetric key generation with KMIP plugin")
        if not self.generate_supports(key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                key_spec.alg)

        if key_spec.alg.lower() not in ss.KeyAlgorithm.ASYMMETRIC_ALGORITHMS:
            raise KMIPSecretStoreError(
                u._("An unsupported algorithm {algorithm} was passed to "
                    "the 'generate_asymmetric_key' method").format(
                        algorithm=key_spec.alg))

        if key_spec.passphrase:
            raise KMIPSecretStoreError(
                u._('KMIP plugin does not currently support protecting the '
                    'private key with a passphrase'))

        algorithm = self._create_cryptographic_algorithm_attribute(
            key_spec.alg)

        length = self._create_cryptographic_length_attribute(
            key_spec.bit_length)

        attributes = [algorithm, length]
        common = CommonTemplateAttribute(
            attributes=attributes)

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for asymmetric " +
                      "secret generation")
            result = self.client.create_key_pair(
                common_template_attribute=common,
                credential=self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                LOG.debug("SUCCESS: Asymmetric key pair generated with "
                          "public key uuid: %s and private key uuid: %s",
                          result.public_key_uuid.value,
                          result.private_key_uuid.value)
                private_key_metadata = {
                    KMIPSecretStore.KEY_UUID:
                    result.private_key_uuid.value}
                public_key_metadata = {
                    KMIPSecretStore.KEY_UUID:
                    result.public_key_uuid.value}
                passphrase_metadata = None
                return ss.AsymmetricKeyMetadataDTO(private_key_metadata,
                                                   public_key_metadata,
                                                   passphrase_metadata)
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for asymmetric "
                      "secret generation")

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

        usage_mask = self._create_usage_mask_attribute(object_type)
        attribute_list = [usage_mask]
        template_attribute = TemplateAttribute(
            attributes=attribute_list)
        secret = self._get_kmip_secret(secret_dto)

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret storage")
            result = self.client.register(
                object_type=object_type,
                template_attribute=template_attribute,
                secret=secret,
                credential=self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                LOG.debug("SUCCESS: Key stored with uuid: %s",
                          result.uuid.value)
                return {KMIPSecretStore.KEY_UUID: result.uuid.value}
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for secret storage")

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
        object_type, key_format_enum = self._map_type_ss_to_kmip(secret_type)
        if (key_format_enum is not None and
                object_type != enums.ObjectType.CERTIFICATE):
            key_format_type = misc.KeyFormatType(key_format_enum)
        else:
            key_format_type = None
        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret " +
                      "retrieval")
            result = self.client.get(uuid=uuid,
                                     key_format_type=key_format_type,
                                     credential=self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                ret_secret_dto = self._get_barbican_secret(result, secret_type)
                LOG.debug("SUCCESS: Key retrieved with uuid: %s",
                          uuid)
                return ret_secret_dto
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for secret " +
                      "retrieval")

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
        if (alg_dict_entry and key_spec.bit_length in
                alg_dict_entry.get(KMIPSecretStore.VALID_BIT_LENGTHS)):
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
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret deletion")
            result = self.client.destroy(uuid=uuid,
                                         credential=self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                LOG.debug("SUCCESS: Key with uuid %s deleted", uuid)
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for secret deletion")

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
        object_type, key_format_type = (
            self._map_type_ss_to_kmip(secret_type))

        normalized_secret = self._normalize_secret(secret_dto.secret,
                                                   secret_type)
        kmip_object = None
        if object_type == enums.ObjectType.CERTIFICATE:
            kmip_object = Certificate(
                certificate_type=enums.CertificateTypeEnum.X_509,
                certificate_value=normalized_secret)
        elif object_type == enums.ObjectType.OPAQUE_DATA:
            opaque_type = Opaque.OpaqueDataType(enums.OpaqueDataType.NONE)
            opaque_value = Opaque.OpaqueDataValue(normalized_secret)
            kmip_object = Opaque(opaque_type, opaque_value)
        elif (object_type == enums.ObjectType.SYMMETRIC_KEY or
              object_type == enums.ObjectType.SECRET_DATA or
              object_type == enums.ObjectType.PRIVATE_KEY or
              object_type == enums.ObjectType.PUBLIC_KEY):
            key_material = KeyMaterial(normalized_secret)
            key_value = KeyValue(key_material)

            key_spec = secret_dto.key_spec
            algorithm = None
            if key_spec.alg is not None:
                algorithm_name = self._map_algorithm_ss_to_kmip(
                    key_spec.alg.lower())
                algorithm = CryptographicAlgorithm(algorithm_name)
            bit_length = None
            if key_spec.bit_length is not None:
                bit_length = CryptographicLength(key_spec.bit_length)

            key_block = KeyBlock(
                key_format_type=misc.KeyFormatType(key_format_type),
                key_compression_type=None,
                key_value=key_value,
                cryptographic_algorithm=algorithm,
                cryptographic_length=bit_length,
                key_wrapping_data=None)

            if object_type == enums.ObjectType.SYMMETRIC_KEY:
                kmip_object = SymmetricKey(key_block)
            elif object_type == enums.ObjectType.PRIVATE_KEY:
                kmip_object = PrivateKey(key_block)
            elif object_type == enums.ObjectType.PUBLIC_KEY:
                kmip_object = PublicKey(key_block)
            elif object_type == enums.ObjectType.SECRET_DATA:
                kind = SecretData.SecretDataType(enums.SecretDataType.PASSWORD)
                return SecretData(secret_data_type=kind,
                                  key_block=key_block)

        return kmip_object

    def _get_barbican_secret(self, result, secret_type):
        object_type = result.object_type.value
        if object_type == enums.ObjectType.CERTIFICATE.value:
            certificate = result.secret
            secret_value = certificate.certificate_value.value
            key_spec = ss.KeySpec()
        elif object_type == enums.ObjectType.OPAQUE_DATA.value:
            opaque_secret = result.secret
            secret_value = opaque_secret.opaque_data_value.value
            key_spec = ss.KeySpec()
        elif (object_type == enums.ObjectType.SYMMETRIC_KEY.value or
              object_type == enums.ObjectType.PRIVATE_KEY.value or
              object_type == enums.ObjectType.PUBLIC_KEY.value or
              object_type == enums.ObjectType.SECRET_DATA.value):

            secret_block = result.secret.key_block
            key_value_type = type(secret_block.key_value.key_material)
            if (key_value_type == KeyMaterialStruct or
                    key_value_type == KeyMaterial):
                secret_value = secret_block.key_value.key_material.value
            else:
                msg = u._(
                    "Unknown key value type received from KMIP "
                    "server, expected {key_value_struct} or "
                    "{key_value_string}, received: {key_value_type}"
                ).format(
                    key_value_struct=KeyValue,
                    key_value_string=KeyMaterial,
                    key_value_type=key_value_type
                )
                LOG.exception(msg)
                raise ss.SecretGeneralException(msg)

            if secret_block.cryptographic_algorithm:
                secret_alg = self._map_algorithm_kmip_to_ss(
                    secret_block.cryptographic_algorithm.value)
            else:
                secret_alg = None
            if secret_block.cryptographic_length:
                secret_bit_length = secret_block.cryptographic_length.value
            else:
                secret_bit_length = None
            key_spec = ss.KeySpec(secret_alg, secret_bit_length),

        secret_value = self._denormalize_secret(secret_value, secret_type)
        secret_dto = ss.SecretDTO(
            secret_type,
            secret_value,
            key_spec,
            content_type=None,
            transport_key=None)
        return secret_dto

    def _create_cryptographic_algorithm_attribute(self, alg):
        """Creates a KMIP Cryptographic Algorithm attribute.

        This attribute is used when telling the KMIP server what kind of
        key to generate.
        :param algorithm: A SecretStore KeyAlgorithm enum value
        :returns: A KMIP Cryptographic Algorithm attribute
        """
        attribute_type = enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM
        algorithm_name = self._map_algorithm_ss_to_kmip(alg.lower())
        algorithm = attributes.AttributeFactory().create_attribute(
            attribute_type,
            algorithm_name)
        LOG.debug(attribute_debug_msg,
                  attribute_type.value,
                  algorithm_name.name)
        return algorithm

    def _create_usage_mask_attribute(self, kmip_type):
        """Creates a KMIP Usage Mask attribute.

        :param kmip_type: A PyKMIP enums ObjectType value
        :returns: A KMIP Usage Mask attribute specific to the object type
        """
        if (kmip_type == enums.ObjectType.SYMMETRIC_KEY or
                kmip_type == enums.ObjectType.SECRET_DATA or
                kmip_type == enums.ObjectType.OPAQUE_DATA):
            flags = [enums.CryptographicUsageMask.ENCRYPT,
                     enums.CryptographicUsageMask.DECRYPT]
        elif (kmip_type == enums.ObjectType.PUBLIC_KEY or
                kmip_type == enums.ObjectType.CERTIFICATE):
            flags = [enums.CryptographicUsageMask.ENCRYPT,
                     enums.CryptographicUsageMask.VERIFY]
        elif kmip_type == enums.ObjectType.PRIVATE_KEY:
            flags = [enums.CryptographicUsageMask.DECRYPT,
                     enums.CryptographicUsageMask.SIGN]

        attribute_type = enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = attributes.AttributeFactory().create_attribute(
            attribute_type,
            flags)
        LOG.debug(attribute_debug_msg,
                  attribute_type.value,
                  ', '.join(map(str, flags)))
        return usage_mask

    def _create_cryptographic_length_attribute(self, bit_length):
        """Creates a KMIP Cryptographic Length attribute.

        This attribute is used when telling the KMIP server what kind of
        key to generate.
        :param bit_length: Bit length of the secret's algorithm
        :returns: KMIP Cryptographic Length attribute
        """
        attribute_type = enums.AttributeType.CRYPTOGRAPHIC_LENGTH
        length = attributes.AttributeFactory().create_attribute(
            attribute_type,
            int(bit_length))
        LOG.debug(attribute_debug_msg,
                  attribute_type.value,
                  bit_length)
        return length

    def _map_type_ss_to_kmip(self, object_type):
        """Map SecretType to KMIP type enum

        Returns None if the type is not supported. The KMIP plugin only
        supports symmetric and asymmetric keys for now.
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

    def _map_algorithm_ss_to_kmip(self, algorithm):
        """Map SecretStore enum value to the KMIP algorithm enum

        Returns None if the algorithm is not supported.
        :param algorithm: SecretStore algorithm enum value
        :returns: KMIP algorithm enum value if supported, None if not
        supported
        """
        alg_dict_entry = self.valid_alg_dict.get(algorithm, None)
        if alg_dict_entry:
            return alg_dict_entry.get(KMIPSecretStore.KMIP_ALGORITHM_ENUM)
        else:
            return None

    def _map_algorithm_kmip_to_ss(self, algorithm):
        """Map KMIP algorithm enum to SecretStore algorithm enum

        Returns None if the algorithm is not supported.
        :param algorithm: KMIP algorithm enum
        :returns: SecretStore algorithm enum value if supported, None if not
        supported
        """
        for ss_alg, ss_dict in six.iteritems(self.valid_alg_dict):
            if ss_dict.get(KMIPSecretStore.KMIP_ALGORITHM_ENUM) == algorithm:
                return ss_alg
        return None

    def _raise_secret_general_exception(self, result):
        msg = u._(
            "Status: {status}, Reason: {reason}, "
            "Message: {message}"
        ).format(
            status=result.result_status,
            reason=result.result_reason,
            message=result.result_message
        )
        LOG.error(u._LE("ERROR from KMIP server: %s"), msg)
        raise ss.SecretGeneralException(msg)

    def _validate_keyfile_permissions(self, path):
        """Check that file has permissions appropriate for a sensitive key

        Key files are extremely sensitive, they should be owned by the user
        who they relate to. They should be readable only (to avoid accidental
        changes). They should not be readable or writeable by any other user.

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
