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

import mock
import testtools

from barbican.plugin.interface import secret_store
from barbican.tests import utils

try:
    from kmip.core import attributes as attr
    from kmip.core import enums
    from kmip.core.factories import attributes
    from kmip.core.factories import keys
    from kmip.core.messages import contents
    from kmip.core import objects
    from kmip.core import secrets
    from kmip.services.kmip_client import KMIPProxy
    from kmip.services import results

    from barbican.plugin import kmip_secret_store as kss
    kmip_available = True
except ImportError:
    kmip_available = False


@testtools.skipIf(not kmip_available, "KMIP imports not available")
class WhenTestingKMIPSecretStore(utils.BaseTestCase):
    """Test using the KMIP server backend for SecretStore."""

    def setUp(self):
        super(WhenTestingKMIPSecretStore, self).setUp()

        self.kmipclient_mock = mock.MagicMock(name="KMIP client mock")

        self.credential = None

        self.secret_store = kss.KMIPSecretStore()
        self.secret_store.client = self.kmipclient_mock
        self.secret_store.credential = self.credential

        self.sample_secret = secrets.SecretData(
            key_block=objects.KeyBlock(
                cryptographic_algorithm=attr.CryptographicAlgorithm(),
                cryptographic_length=attr.CryptographicLength(128),
                key_value=objects.KeyValue(
                    key_value=objects.KeyValueStruct(
                        key_material=keys.KeyFactory().create_key(
                            enums.KeyFormatType.RAW)))))

        self.secret_store.client.create = mock.create_autospec(
            KMIPProxy.create, return_value=results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier('uuid')))

        self.secret_store.client.register = mock.create_autospec(
            KMIPProxy.register, return_value=results.RegisterResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier('uuid')))

        self.secret_store.client.destroy = mock.create_autospec(
            KMIPProxy.destroy, return_value=results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)))

        self.secret_store.client.get = mock.create_autospec(
            KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                object_type=attr.ObjectType(),
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
                                        56, 'mode')
        for x in [56, 112, 168]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_with_invalid_alg(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DSA,
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

        self.kmipclient_mock.create.assert_called_once_with(
            enums.ObjectType.SYMMETRIC_KEY,
            mock.ANY,
            self.credential)

    def test_generate_symmetric_key_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        return_value = self.secret_store.generate_symmetric_key(key_spec)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(0, cmp(expected, return_value))

    def test_generate_symmetric_key_error_occurs(self):
        self.secret_store.client.create = mock.create_autospec(
            KMIPProxy.create, return_value=results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.generate_symmetric_key,
            key_spec)

    def test_generate_symmetric_key_invalid_algorithm(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DSA,
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

    # ---------------- TEST GENERATE_ASYMMETRIC ------------------------------

    def test_generate_asymmetric_key(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        self.assertRaises(
            NotImplementedError,
            self.secret_store.generate_asymmetric_key,
            key_spec
        )

    # ----------------- TEST STORE -------------------------------------------

    def test_store_secret_assert_called(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            "AAAA",
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.secret_store.store_secret(secret_dto)
        self.kmipclient_mock.register.assert_called_once_with(
            enums.ObjectType.SYMMETRIC_KEY,
            mock.ANY,
            mock.ANY,
            self.credential)

    def test_store_secret_return_value(self):
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

    def test_store_secret_error_occurs(self):
        self.secret_store.client.register = mock.create_autospec(
            KMIPProxy.register, return_value=results.RegisterResult(
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

    # --------------- TEST GET -----------------------------------------------

    def test_get_with_null_metadata_values(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: None}
        self.assertRaises(
            TypeError,
            self.secret_store.get_secret,
            metadata
        )

    def test_get_secret_symmetric_assert_called(self):
        self.secret_store._map_type_kmip_to_ss = mock.MagicMock(
            return_value="symmetric")
        self.secret_store._map_algorithm_kmip_to_ss = mock.MagicMock(
            return_value="aes")
        self.secret_store._convert_byte_array_to_base64 = mock.MagicMock(
            return_value="AAAA")
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        self.secret_store.get_secret(metadata)
        self.kmipclient_mock.get.assert_called_once_with('uuid',
                                                         self.credential)

    def test_get_secret_symmetric_return_value(self):
        self.secret_store._map_type_kmip_to_ss = mock.MagicMock(
            return_value="symmetric")
        self.secret_store._map_algorithm_kmip_to_ss = mock.MagicMock(
            return_value="aes")
        self.secret_store._convert_byte_array_to_base64 = mock.MagicMock(
            return_value="AAAA")
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        return_value = self.secret_store.get_secret(metadata)
        self.assertEqual(secret_store.SecretDTO, type(return_value))
        self.assertEqual(secret_store.SecretType.SYMMETRIC, return_value.type)

    def test_get_secret_symmetric_error_occurs(self):
        self.secret_store.client.get = mock.create_autospec(
            KMIPProxy.get, return_value=results.GetResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            metadata)

    # ---------------- TEST DELETE -------------------------------------------

    def test_delete_with_null_metadata_values(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: None}
        self.assertEqual(None, self.secret_store.delete_secret(metadata))

    def test_delete_secret_assert_called(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        self.secret_store.delete_secret(metadata)
        self.kmipclient_mock.destroy.assert_called_once_with('uuid',
                                                             self.credential)

    def test_delete_secret_return_value(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        return_value = self.secret_store.delete_secret(metadata)
        self.assertEqual(None, return_value)

    def test_delete_secret_error_occurs(self):
        self.secret_store.client.destroy = mock.create_autospec(
            KMIPProxy.destroy, return_value=results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.OPERATION_FAILED)))
        metadata = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.delete_secret,
            metadata)
