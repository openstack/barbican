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
import base64
import socket
import stat

import mock

from barbican.plugin.interface import secret_store
from barbican.tests import keys
from barbican.tests import utils

from kmip.core import attributes as attr
from kmip.core import enums
from kmip.core.factories import attributes
from kmip.core.messages import contents
from kmip.core import misc
from kmip.core import objects
from kmip.core import secrets
from kmip.services import kmip_client as proxy
from kmip.services import results
from oslo_config import cfg

from barbican.plugin import kmip_secret_store as kss


def get_sample_symmetric_key():
    key_material = objects.KeyMaterial(base64.b64decode(
        utils.get_symmetric_key()))
    key_value = objects.KeyValue(key_material)
    key_block = objects.KeyBlock(
        key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
        key_compression_type=None,
        key_value=key_value,
        cryptographic_algorithm=attr.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.AES),
        cryptographic_length=attr.CryptographicLength(128),
        key_wrapping_data=None)
    return secrets.SymmetricKey(key_block)


def get_sample_public_key():
    key_material = objects.KeyMaterial(keys.get_public_key_der())
    key_value = objects.KeyValue(key_material)
    key_block = objects.KeyBlock(
        key_format_type=misc.KeyFormatType(enums.KeyFormatType.X_509),
        key_compression_type=None,
        key_value=key_value,
        cryptographic_algorithm=attr.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA),
        cryptographic_length=attr.CryptographicLength(2048),
        key_wrapping_data=None)
    return secrets.PublicKey(key_block)


def get_sample_private_key():
    key_material = objects.KeyMaterial(keys.get_private_key_der())
    key_value = objects.KeyValue(key_material)
    key_block = objects.KeyBlock(
        key_format_type=misc.KeyFormatType(enums.KeyFormatType.PKCS_8),
        key_compression_type=None,
        key_value=key_value,
        cryptographic_algorithm=attr.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA),
        cryptographic_length=attr.CryptographicLength(2048),
        key_wrapping_data=None)
    return secrets.PrivateKey(key_block)


@utils.parameterized_test_case
class WhenTestingKMIPSecretStore(utils.BaseTestCase):
    """Test using the KMIP server backend for SecretStore."""

    def setUp(self):
        super(WhenTestingKMIPSecretStore, self).setUp()

        self.expected_username = "sample_username"
        self.expected_password = "sample_password"

        CONF = cfg.CONF
        CONF.kmip_plugin.username = self.expected_username
        CONF.kmip_plugin.password = self.expected_password
        CONF.kmip_plugin.keyfile = None

        self.secret_store = kss.KMIPSecretStore(CONF)
        self.credential = self.secret_store.credential
        self.symmetric_type = secret_store.SecretType.SYMMETRIC

        self.sample_secret_features = {
            'key_format_type': enums.KeyFormatType.RAW,
            'key_value': {
                'bytes': bytearray(b'\x00\x00\x00')
            },
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
            'cryptographic_length': 128
        }

        self.symmetric_key_uuid = 'dde870ad-cea3-41a3-9bb9-e8ab579a2f91'
        self.public_key_uuid = 'cb908abb-d363-4d9f-8ef2-5e84d27dd25c'
        self.private_key_uuid = '2d4c0544-4ec6-45b7-81cd-b23c75744eac'

        self.sample_secret = get_sample_symmetric_key()

        self.secret_store.client.open = mock.MagicMock(proxy.KMIPProxy.open)
        self.secret_store.client.close = mock.MagicMock(proxy.KMIPProxy.close)

        self.secret_store.client.create = mock.MagicMock(
            proxy.KMIPProxy.create, return_value=results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier(
                    self.symmetric_key_uuid)))

        self.secret_store.client.create_key_pair = mock.MagicMock(
            proxy.KMIPProxy.create_key_pair,
            return_value=results.CreateKeyPairResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                private_key_uuid=attr.UniqueIdentifier(self.private_key_uuid),
                public_key_uuid=attr.UniqueIdentifier(self.public_key_uuid)))

        self.secret_store.client.register = mock.MagicMock(
            proxy.KMIPProxy.register, return_value=results.RegisterResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier('uuid')))

        self.secret_store.client.destroy = mock.MagicMock(
            proxy.KMIPProxy.destroy, return_value=results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)))

        self.secret_store.client.get = mock.MagicMock(
            proxy.KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                object_type=attr.ObjectType(enums.ObjectType.SYMMETRIC_KEY),
                secret=self.sample_secret))

        self.attribute_factory = attributes.AttributeFactory()

    # --------------- TEST GENERATE_SUPPORTS ---------------------------------

    def test_generate_supports_aes(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        None, 'mode')
        for x in [128, 192, 256]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_des(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DES,
                                        None, 'mode')
        for x in [56]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_desede(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DESEDE,
                                        None, 'mode')
        for x in [56, 112, 168]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_rsa(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        None, 'mode')
        for x in [1024, 2048, 3072, 4096]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_dsa(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DSA,
                                        None, 'mode')
        for x in [1024, 2048, 3072]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_with_invalid_alg(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.HMACSHA1,
                                        56, 'mode')
        self.assertFalse(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_with_valid_alg_invalid_bit_length(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        56, 'mode')
        self.assertFalse(self.secret_store.generate_supports(key_spec))

    # ------------ TEST GENERATE_SYMMETRIC -----------------------------------

    def test_generate_symmetric_key_assert_called(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.secret_store.generate_symmetric_key(key_spec)

        self.secret_store.client.create.assert_called_once_with(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=mock.ANY,
            credential=self.credential)

    def test_generate_symmetric_key_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        return_value = self.secret_store.generate_symmetric_key(key_spec)
        expected = {kss.KMIPSecretStore.KEY_UUID:
                    self.symmetric_key_uuid}

        self.assertEqual(expected, return_value)

    def test_generate_symmetric_key_server_error_occurs(self):
        self.secret_store.client.create = mock.MagicMock(
            proxy.KMIPProxy.create, return_value=results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.generate_symmetric_key,
            key_spec)

    def test_generate_symmetric_key_invalid_algorithm(self):
        key_spec = secret_store.KeySpec('invalid_algorithm',
                                        128, 'mode')
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.generate_symmetric_key,
            key_spec)

    def test_generate_symmetric_key_valid_algorithm_invalid_bit_length(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        56, 'mode')
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.generate_symmetric_key,
            key_spec)

    def test_generate_symmetric_key_not_symmetric_algorithm(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode')
        self.assertRaises(
            kss.KMIPSecretStoreError,
            self.secret_store.generate_symmetric_key,
            key_spec)

    def test_generate_symmetric_key_error_opening_connection(self):
        self.secret_store.client.open = mock.Mock(side_effect=socket.error)

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.generate_symmetric_key,
            key_spec)

    # ---------------- TEST GENERATE_ASYMMETRIC ------------------------------

    def test_generate_asymmetric_key_assert_called(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode')
        self.secret_store.generate_asymmetric_key(key_spec)

        self.secret_store.client.create_key_pair.assert_called_once_with(
            common_template_attribute=mock.ANY,
            credential=self.credential)

    def test_generate_asymmetric_key_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode')
        return_value = self.secret_store.generate_asymmetric_key(key_spec)
        expected_private_key_meta = {
            kss.KMIPSecretStore.KEY_UUID:
            self.private_key_uuid}
        expected_public_key_meta = {
            kss.KMIPSecretStore.KEY_UUID:
            self.public_key_uuid}
        expected_passphrase_meta = None

        self.assertEqual(
            expected_private_key_meta, return_value.private_key_meta)
        self.assertEqual(
            expected_public_key_meta, return_value.public_key_meta)
        self.assertEqual(
            expected_passphrase_meta, return_value.passphrase_meta)

    def test_generate_asymmetric_key_server_error_occurs(self):
        self.secret_store.client.create_key_pair = mock.MagicMock(
            proxy.KMIPProxy.create_key_pair,
            return_value=results.CreateKeyPairResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode')
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_invalid_algorithm(self):
        key_spec = secret_store.KeySpec('invalid_algorithm', 160, 'mode')
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_valid_algorithm_invalid_bit_length(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        56, 'mode')
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_not_asymmetric_algorithm(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.assertRaises(
            kss.KMIPSecretStoreError,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_check_for_passphrase(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode', 'passphrase')
        self.assertRaises(
            kss.KMIPSecretStoreError,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_error_opening_connection(self):
        self.secret_store.client.open = mock.Mock(side_effect=socket.error)

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode')
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    # ----------------- TEST STORE -------------------------------------------

    def test_store_symmetric_secret_assert_called(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=mock.ANY,
            secret=mock.ANY,
            credential=self.credential)

    def test_store_symmetric_secret_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(0, cmp(expected, return_value))

    def test_store_private_key_secret_assert_called(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA, 2048)
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.PRIVATE,
                                            base64.b64encode(
                                                keys.get_private_key_pem()),
                                            key_spec,
                                            'content_type')
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            object_type=enums.ObjectType.PRIVATE_KEY,
            template_attribute=mock.ANY,
            secret=mock.ANY,
            credential=self.credential)

    def test_store_private_key_secret_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA, 2048)
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.PRIVATE,
                                            base64.b64encode(
                                                keys.get_private_key_pem()),
                                            key_spec,
                                            'content_type')
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(0, cmp(expected, return_value))

    def test_store_secret_server_error_occurs(self):
        self.secret_store.client.register = mock.MagicMock(
            proxy.KMIPProxy.register, return_value=results.RegisterResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')

        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.store_secret,
            secret_dto)

    def test_store_secret_invalid_algorithm(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DSA,
                                        128, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.store_secret,
            secret_dto)

    def test_store_secret_invalid_object_type(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.OPAQUE,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.assertRaises(
            kss.KMIPSecretStoreError,
            self.secret_store.store_secret,
            secret_dto)

    def test_store_secret_valid_algorithm_invalid_bit_length(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        56, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.assertRaises(
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.store_secret,
            secret_dto)

    def test_store_secret_error_opening_connection(self):
        self.secret_store.client.open = mock.Mock(side_effect=socket.error)

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')

        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.store_secret,
            secret_dto)

    # --------------- TEST GET -----------------------------------------------

    @utils.parameterized_dataset({
        'symmetric': [get_sample_symmetric_key(),
                      secret_store.SecretType.SYMMETRIC,
                      misc.KeyFormatType(enums.KeyFormatType.RAW),
                      utils.get_symmetric_key()],
        'public_key': [get_sample_public_key(),
                       secret_store.SecretType.PUBLIC,
                       misc.KeyFormatType(enums.KeyFormatType.X_509),
                       base64.b64encode(keys.get_public_key_pem())],
        'private_key': [get_sample_private_key(),
                        secret_store.SecretType.PRIVATE,
                        misc.KeyFormatType(enums.KeyFormatType.PKCS_8),
                        base64.b64encode(keys.get_private_key_pem())],
        'opaque': [get_sample_symmetric_key(),
                   secret_store.SecretType.OPAQUE,
                   None,
                   utils.get_symmetric_key()]
    })
    def test_get_secret(self, returned_secret, secret_type,
                        key_format_type, expected_secret):
        object_type, _ = self.secret_store._map_type_ss_to_kmip(secret_type)
        self.secret_store.client.get = mock.MagicMock(
            proxy.KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                object_type=attr.ObjectType(object_type),
                secret=returned_secret))
        uuid = utils.generate_test_uuid(0)
        metadata = {kss.KMIPSecretStore.KEY_UUID: uuid}
        secret_dto = self.secret_store.get_secret(secret_type, metadata)

        self.secret_store.client.get.assert_called_once_with(
            uuid=uuid,
            key_format_type=key_format_type,
            credential=self.credential)

        self.assertEqual(secret_store.SecretDTO, type(secret_dto))
        self.assertEqual(secret_type, secret_dto.type)
        self.assertEqual(expected_secret, secret_dto.secret)

    def test_get_secret_symmetric_return_value_invalid_key_material_type(self):
        sample_secret = self.sample_secret
        sample_secret.key_block.key_value.key_material = 'invalid_type'
        self.secret_store.client.get = mock.MagicMock(
            proxy.KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                object_type=attr.ObjectType(enums.ObjectType.SYMMETRIC_KEY),
                secret=sample_secret))

        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    def test_get_secret_symmetric_server_error_occurs(self):
        self.secret_store.client.get = mock.MagicMock(
            proxy.KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    def test_get_secret_symmetric_error_opening_connection(self):
        self.secret_store.client.open = mock.Mock(side_effect=socket.error)

        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    # ---------------- TEST DELETE -------------------------------------------

    def test_delete_with_null_metadata_values(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: None}
        self.assertEqual(None, self.secret_store.delete_secret(metadata))

    def test_delete_secret_assert_called(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.secret_store.delete_secret(metadata)
        self.secret_store.client.destroy.assert_called_once_with(
            uuid=self.symmetric_key_uuid,
            credential=self.credential)

    def test_delete_secret_return_value(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        return_value = self.secret_store.delete_secret(metadata)
        self.assertEqual(None, return_value)

    def test_delete_secret_server_error_occurs(self):
        self.secret_store.client.destroy = mock.MagicMock(
            proxy.KMIPProxy.destroy, return_value=results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.delete_secret,
            metadata)

    def test_delete_secret_error_opening_connection(self):
        self.secret_store.client.open = mock.Mock(side_effect=socket.error)
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.delete_secret,
            metadata)

    # -------------- TEST HELPER FUNCTIONS -----------------------------------

    def test_credential(self):
        actual_credential = self.secret_store.credential

        self.assertEqual(
            enums.CredentialType.USERNAME_AND_PASSWORD.value,
            actual_credential.credential_type.value)
        self.assertEqual(
            self.expected_username,
            actual_credential.credential_value.username.value)
        self.assertEqual(
            self.expected_password,
            actual_credential.credential_value.password.value)

    def test_credential_None(self):
        CONF = cfg.CONF
        CONF.kmip_plugin.username = None
        CONF.kmip_plugin.password = None
        CONF.kmip_plugin.keyfile = None

        secret_store = kss.KMIPSecretStore(CONF)
        self.assertIsNone(secret_store.credential)

    def test_map_type_ss_to_kmip_valid_type(self):
        ss_types = [secret_store.SecretType.SYMMETRIC,
                    secret_store.SecretType.PUBLIC,
                    secret_store.SecretType.PRIVATE]
        for ss_type in ss_types:
            self.assertIsNotNone(
                self.secret_store._map_type_ss_to_kmip(ss_type))

    def test_map_type_ss_to_kmip_invalid_type(self):
        object_type, key_format_type = (
            self.secret_store._map_type_ss_to_kmip('bad_type'))
        self.assertIsNone(object_type)
        self.assertIsNone(key_format_type)

    def test_map_algorithm_ss_to_kmip_valid_alg(self):
        ss_algs = [secret_store.KeyAlgorithm.AES,
                   secret_store.KeyAlgorithm.DES,
                   secret_store.KeyAlgorithm.DESEDE,
                   secret_store.KeyAlgorithm.RSA,
                   secret_store.KeyAlgorithm.DSA]
        for alg in ss_algs:
            self.assertIsNotNone(
                self.secret_store._map_algorithm_ss_to_kmip(alg))

    def test_map_algorithm_ss_to_kmip_invalid_alg(self):
        self.assertIsNone(
            self.secret_store._map_algorithm_ss_to_kmip('bad_alg'))

    def test_map_algorithm_kmip_to_ss_valid_alg(self):
        kmip_algs = [enums.CryptographicAlgorithm.AES,
                     enums.CryptographicAlgorithm.DES,
                     enums.CryptographicAlgorithm.TRIPLE_DES]
        for alg in kmip_algs:
            self.assertIsNotNone(
                self.secret_store._map_algorithm_kmip_to_ss(alg))

    def test_map_algorithm_kmip_to_ss_invalid_alg(self):
        self.assertIsNone(
            self.secret_store._map_algorithm_kmip_to_ss('bad_alg'))

    def test_validate_keyfile_permissions_good(self):
        config = {'return_value.st_mode':
                  (stat.S_IRUSR | stat.S_IFREG)}

        with mock.patch('os.stat', **config):
            self.assertIsNone(
                self.secret_store._validate_keyfile_permissions('/some/path/'))

    def test_check_keyfile_permissions_bad(self):
        config = {'return_value.st_mode':
                  (stat.S_IWOTH | stat.S_IFREG)}

        with mock.patch('os.stat', **config):
            self.assertRaises(
                kss.KMIPSecretStoreError,
                self.secret_store._validate_keyfile_permissions,
                '/some/path/')

    def test_checks_keyfile_permissions(self):
        config = {'return_value': True}
        func = ("barbican.plugin.kmip_secret_store."
                "KMIPSecretStore._validate_keyfile_permissions")

        with mock.patch(func, **config) as m:
            CONF = cfg.CONF
            CONF.kmip_plugin.keyfile = '/some/path'
            kss.KMIPSecretStore(CONF)
            self.assertEqual(len(m.mock_calls), 1)
