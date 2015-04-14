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

from kmip.services import kmip_client

import base64
import os
import stat

from kmip.core import enums
from kmip.core.factories import attributes
from kmip.core.factories import credentials
from kmip.core.factories import secrets
from kmip.core import misc
from kmip.core import objects as kmip_objects
from oslo_config import cfg
from oslo_log import log

from barbican import i18n as u  # noqa
from barbican.plugin.interface import secret_store as ss

LOG = log.getLogger(__name__)

CONF = cfg.CONF

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
               )
]
CONF.register_group(kmip_opt_group)
CONF.register_opts(kmip_opts, group=kmip_opt_group)

attribute_debug_msg = "Created attribute type %s with value %s"


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

        usage_mask = self._create_usage_mask_attribute()

        length = self._create_cryptographic_length_attribute(
            key_spec.bit_length)

        attribute_list = [algorithm, usage_mask, length]
        template_attribute = kmip_objects.TemplateAttribute(
            attributes=attribute_list)

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret " +
                      "generation")
            result = self.client.create(object_type=object_type,
                                        template_attribute=template_attribute,
                                        credential=self.credential)
        except Exception as e:
            LOG.exception("Error opening or writing to client")
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

        usage_mask = self._create_usage_mask_attribute()

        length = self._create_cryptographic_length_attribute(
            key_spec.bit_length)

        attributes = [algorithm, usage_mask, length]
        common = kmip_objects.CommonTemplateAttribute(
            attributes=attributes)

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for asymmetric " +
                      "secret generation")
            result = self.client.create_key_pair(
                common_template_attribute=common,
                credential=self.credential)
        except Exception as e:
            LOG.exception("Error opening or writing to client")
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

        algorithm_value = self._map_algorithm_ss_to_kmip(
            secret_dto.key_spec.alg)

        usage_mask = self._create_usage_mask_attribute()

        attribute_list = [usage_mask]
        template_attribute = kmip_objects.TemplateAttribute(
            attributes=attribute_list)

        normalized_secret = base64.b64decode(secret_dto.secret)

        secret_features = {
            'key_format_type': key_format_type,
            'key_value': {
                'bytes': normalized_secret
            },
            'cryptographic_algorithm': algorithm_value,
            'cryptographic_length': secret_dto.key_spec.bit_length
        }

        secret = secrets.SecretFactory().create(object_type, secret_features)
        LOG.debug("Created secret object to be stored: %s, %s, %s",
                  secret_features.get('key_format_type'),
                  secret_features.get('cryptographic_algorithm'),
                  secret_features.get('cryptographic_length'))

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
        if key_format_enum is not None:
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
                secret_block = result.secret.key_block

                key_value_type = type(secret_block.key_value.key_material)
                if (key_value_type == kmip_objects.KeyMaterialStruct or
                        key_value_type == kmip_objects.KeyMaterial):
                    secret_value = base64.b64encode(
                        secret_block.key_value.key_material.value)
                else:
                    msg = u._(
                        "Unknown key value type received from KMIP "
                        "server, expected {key_value_struct} or "
                        "{key_value_string}, received: {key_value_type}"
                    ).format(
                        key_value_struct=kmip_objects.KeyValue,
                        key_value_string=kmip_objects.KeyMaterial,
                        key_value_type=key_value_type
                    )
                    LOG.exception(msg)
                    raise ss.SecretGeneralException(msg)

                secret_alg = self._map_algorithm_kmip_to_ss(
                    secret_block.cryptographic_algorithm.value)
                secret_bit_length = secret_block.cryptographic_length.value
                ret_secret_dto = ss.SecretDTO(
                    secret_type,
                    secret_value,
                    ss.KeySpec(secret_alg, secret_bit_length),
                    content_type=None,
                    transport_key=None)
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

        For now, only symmetric and asymmetric keys are supported.
        :param key_spec: KeySpec of secret to be stored
        :returns: boolean indicating if secret can be stored
        """
        return self.generate_supports(key_spec)

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

    def _create_usage_mask_attribute(self):
        """Creates a KMIP Usage Mask attribute.

        For now, we assume the key will only be used for encryption and
        decryption. This attribute is used when telling the KMIP server
        what kind of key to generate or store.
        :returns: A KMIP Usage Mask attribute with values ENCRYPT and DECRYPT
        """
        attribute_type = enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        mask_flags = [enums.CryptographicUsageMask.ENCRYPT,
                      enums.CryptographicUsageMask.DECRYPT]
        usage_mask = attributes.AttributeFactory().create_attribute(
            attribute_type,
            mask_flags)
        LOG.debug(attribute_debug_msg,
                  attribute_type.value,
                  ', '.join(map(str, mask_flags)))
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
            return enums.ObjectType.PRIVATE_KEY, enums.KeyFormatType.PKCS_8
        elif object_type == ss.SecretType.PUBLIC:
            return enums.ObjectType.PUBLIC_KEY, enums.KeyFormatType.X_509
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
        for ss_alg, ss_dict in self.valid_alg_dict.iteritems():
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
        LOG.debug("ERROR from KMIP server: %s", msg)
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
