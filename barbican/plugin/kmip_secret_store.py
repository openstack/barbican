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
from kmip.core import objects as kmip_objects


from barbican import i18n as u  # noqa
from barbican.openstack.common import log as logging
from barbican.plugin.interface import secret_store as ss

LOG = logging.getLogger(__name__)

from oslo.config import cfg

CONF = cfg.CONF

kmip_opt_group = cfg.OptGroup(name='kmip_plugin', title='KMIP Plugin')
kmip_opts = [
    cfg.StrOpt('username',
               default='admin',
               help=u._('The default username for authenticating with KMIP')
               ),
    cfg.StrOpt('password',
               default='password',
               help=u._('The default password for authenticating with KMIP')
               ),
    cfg.StrOpt('host',
               default='localhost',
               help=u._('Address of the KMIP server')
               ),
    cfg.StrOpt('port',
               default='9090',
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
                enums.CryptographicAlgorithm.TRIPLE_DES}
        }

        if conf.kmip_plugin.keyfile is not None:
            self._check_keyfile_permissions(conf.kmip_plugin.keyfile)

        credential_type = credentials.CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': conf.kmip_plugin.username,
                            'Password': conf.kmip_plugin.password}
        self.credential = credentials.CredentialFactory().create_credential(
            credential_type,
            credential_value)
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
            result = self.client.create(object_type,
                                        template_attribute,
                                        self.credential)
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
        raise NotImplementedError(
            u._("Feature not yet implemented by KMIP Secret Store plugin"))

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

        object_type = self._map_type_ss_to_kmip(secret_dto.type)

        algorithm_value = self._map_algorithm_ss_to_kmip(
            secret_dto.key_spec.alg)

        usage_mask = self._create_usage_mask_attribute()

        attribute_list = [usage_mask]
        template_attribute = kmip_objects.TemplateAttribute(
            attributes=attribute_list)

        secret_features = {
            'key_format_type': enums.KeyFormatType.RAW,
            'key_value': {
                'bytes': self._convert_base64_to_byte_array(secret_dto.secret)
            },
            'cryptographic_algorithm': algorithm_value,
            'cryptographic_length': secret_dto.key_spec.bit_length
        }

        secret = secrets.SecretFactory().create_secret(object_type,
                                                       secret_features)
        LOG.debug("Created secret object to be stored: %s, %s, %s",
                  secret_features.get('key_format_type'),
                  secret_features.get('cryptographic_algorithm'),
                  secret_features.get('cryptographic_length'))

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret storage")
            result = self.client.register(object_type,
                                          template_attribute,
                                          secret,
                                          self.credential)
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

    def get_secret(self, secret_metadata):
        """Gets a secret

        :param secret_metadata: Dictionary of key metadata, requires:
        {'key_uuid': <uuid of key>}
        :returns: SecretDTO of the retrieved Secret
        :raises: SecretGeneralException
        """
        LOG.debug("Starting secret retrieval with KMIP plugin")
        uuid = str(secret_metadata[KMIPSecretStore.KEY_UUID])

        try:
            self.client.open()
            LOG.debug("Opened connection to KMIP client for secret " +
                      "retrieval")
            result = self.client.get(uuid, self.credential)
        except Exception as e:
            LOG.exception(u._LE("Error opening or writing to client"))
            raise ss.SecretGeneralException(str(e))
        else:
            if result.result_status.enum == enums.ResultStatus.SUCCESS:
                secret_block = result.secret.key_block

                secret_type = self._map_type_kmip_to_ss(
                    result.object_type.enum)

                key_value_type = type(secret_block.key_value.key_value)
                if key_value_type == kmip_objects.KeyValueStruct:
                    secret_value = self._convert_byte_array_to_base64(
                        secret_block.key_value.key_value.key_material.value)

                elif key_value_type == kmip_objects.KeyValueString:
                    secret_value = self._convert_byte_array_to_base64(
                        secret_block.key_value.key_value.value)

                else:
                    msg = u._(
                        "Unknown key value type received from KMIP "
                        "server, expected {key_value_struct} or "
                        "{key_value_string}, received: {key_value_type}"
                    ).format(
                        key_value_struct=kmip_objects.KeyValueStruct,
                        key_value_string=kmip_objects.KeyValueString,
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
                    'content_type',
                    transport_key=None)
                # TODO(kaitlin-farr) remove 'content-type'
                LOG.debug("SUCCESS: Key retrieved with uuid: %s",
                          uuid)
                return ret_secret_dto
            else:
                self._raise_secret_general_exception(result)
        finally:
            self.client.close()
            LOG.debug("Closed connection to KMIP client for secret " +
                      "retreival")

    def generate_supports(self, key_spec):
        """Key generation supported?

        Specifies whether the plugin supports key generation with the
        given key_spec.

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
            result = self.client.destroy(uuid, self.credential)
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

        For now, only symmetric keys are supported.
        :param key_spec: KeySpec of secret to be stored
        :returns: boolean indicating if secret can be stored
        """
        key_type = ss.KeyAlgorithm().get_secret_type(key_spec.alg.lower())
        if key_type is None or self._map_type_ss_to_kmip(key_type) is None:
            return False
        return self.generate_supports(key_spec)

    def _convert_base64_to_byte_array(self, base64_secret):
        """Converts a base64 string to a byte array.

        KMIP transports secret values as byte arrays, so the key values
        must be converted to a byte array for storage.
        :param base64_secret: base64 value of key
        :returns: bytearray of secret
        """
        return bytearray(base64.b64decode(base64_secret))

    def _convert_byte_array_to_base64(self, byte_array):
        """Converts a byte array to a base64 string.

        KMIP transports secret values as byte arrays, so the key values
        must be converted to base64 strings upon getting a stored secret.
        :param byte_array: bytearray of key value
        :returns: base64 string
        """
        return base64.b64encode(str(byte_array))

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
        supports symmetric keys for now.
        :param object_type: SecretType enum value
        :returns: KMIP type enum if supported, None if not supported
        """
        if object_type == ss.SecretType.SYMMETRIC:
            return enums.ObjectType.SYMMETRIC_KEY
        else:
            return None

    def _map_type_kmip_to_ss(self, object_type):
        """Map KMIP type enum to SecretType enum

        Returns None if the type is not supported. The KMIP plugin only
        supports symmetric keys for now.
        :param object_type: KMIP type enum
        :returns: SecretType enum if type is supported, None if not supported
        """
        if object_type == enums.ObjectType.SYMMETRIC_KEY:
            return ss.SecretType.SYMMETRIC
        else:
            return None

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

    def _check_keyfile_permissions(self, path):
        """Check that file has permissions appropriate for a sensitive key

        Key files are extremely sensitive, they should be owned by the user
        who they relate to. They should be readable only (to avoid accidental
        changes). They should not be readable or writeable by any other user.
        """
        expected = (stat.S_IRUSR | stat.S_IFREG)  # 0o100400
        st = os.stat(path)
        if st.st_mode != expected:
            LOG.warning(u._('Poor key file permissions found, recommend 400 '
                            'for path: {file_path}').format(file_path=path))
