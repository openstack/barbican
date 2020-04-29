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
import ssl
import stat
import testtools
from unittest import mock

from kmip.core import enums
from kmip.pie import client
from kmip.pie import objects

from barbican.plugin.interface import secret_store
from barbican.plugin import kmip_secret_store as kss
from barbican.plugin.util import translations
from barbican.tests import keys
from barbican.tests import utils


def get_sample_opaque_secret():
    return objects.OpaqueObject(
        base64.b64decode(utils.get_symmetric_key()),
        enums.OpaqueDataType.NONE)


def get_sample_symmetric_key(key_b64=utils.get_symmetric_key(),
                             key_length=128,
                             algorithm=enums.CryptographicAlgorithm.AES):
    return objects.SymmetricKey(
        algorithm,
        key_length,
        base64.b64decode(key_b64))


def get_sample_public_key(pkcs1=False):
    if pkcs1:
        public_key_value = kss.get_public_key_der_pkcs1(
            keys.get_public_key_pem())
        key_format_type = enums.KeyFormatType.PKCS_1
    else:
        public_key_value = keys.get_public_key_der()
        key_format_type = enums.KeyFormatType.X_509

    return objects.PublicKey(
        enums.CryptographicAlgorithm.RSA,
        2048,
        public_key_value,
        key_format_type)


def get_sample_private_key(pkcs1=False):
    if pkcs1:
        private_key_value = kss.get_private_key_der_pkcs1(
            keys.get_private_key_pem())
        key_format_type = enums.KeyFormatType.PKCS_1
    else:
        private_key_value = keys.get_private_key_der()
        key_format_type = enums.KeyFormatType.PKCS_8

    return objects.PrivateKey(
        enums.CryptographicAlgorithm.RSA,
        2048,
        private_key_value,
        key_format_type)


def get_sample_certificate():
    return objects.X509Certificate(
        keys.get_certificate_der())


@utils.parameterized_test_case
class WhenTestingKMIPSecretStore(utils.BaseTestCase):
    """Test using the KMIP server backend for SecretStore."""

    def setUp(self):
        super(WhenTestingKMIPSecretStore, self).setUp()

        self.expected_username = "sample_username"
        self.expected_password = "sample_password"

        CONF = kss.CONF
        CONF.kmip_plugin.username = self.expected_username
        CONF.kmip_plugin.password = self.expected_password
        CONF.kmip_plugin.keyfile = None
        CONF.kmip_plugin.pkcs1_only = False

        # get the latest protocol that SSL supports
        protocol_dict = ssl.__dict__.get('_PROTOCOL_NAMES')
        latest_protocol = protocol_dict.get(max(protocol_dict.keys()))
        if not latest_protocol.startswith('PROTOCOL_'):
            latest_protocol = 'PROTOCOL_' + latest_protocol
        CONF.kmip_plugin.ssl_version = latest_protocol

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

        self.secret_store.client.open = mock.MagicMock(
            spec=client.ProxyKmipClient.open)
        self.secret_store.client.close = mock.MagicMock(
            spec=client.ProxyKmipClient.close)

        self.secret_store.client.create = mock.MagicMock(
            return_value=self.symmetric_key_uuid)

        self.secret_store.client.create_key_pair = mock.MagicMock(
            return_value=(self.public_key_uuid, self.private_key_uuid))

        self.secret_store.client.register = mock.MagicMock(
            return_value='uuid')

        self.secret_store.client.destroy = mock.MagicMock(
            return_value=None)

        self.secret_store.client.get = mock.MagicMock(
            return_value=self.sample_secret)

    # --------------- TEST CONFIG OPTIONS ---------------------------------

    def test_enable_pkcs1_only_config_option(self):
        CONF = kss.CONF
        CONF.kmip_plugin.pkcs1_only = True
        secret_store = kss.KMIPSecretStore(CONF)
        self.assertTrue(secret_store.pkcs1_only)

    @testtools.skipIf(not getattr(ssl, "PROTOCOL_TLSv1_2", None),
                      "TLSv1.2 is not available on this system")
    def test_enable_tlsv12_config_option(self):
        ssl_version = "PROTOCOL_TLSv1_2"
        CONF = kss.CONF
        CONF.kmip_plugin.ssl_version = ssl_version
        kss.KMIPSecretStore(CONF)
        self.assertEqual(ssl_version, CONF.kmip_plugin.ssl_version)

    @testtools.skipIf(not getattr(ssl, "PROTOCOL_TLSv1", None),
                      "TLSv1 is not available on this system")
    def test_enable_tlsv1_config_option(self):
        ssl_version = "PROTOCOL_TLSv1"
        CONF = kss.CONF
        CONF.kmip_plugin.ssl_version = ssl_version
        kss.KMIPSecretStore(CONF)
        self.assertEqual(ssl_version, CONF.kmip_plugin.ssl_version)

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
        for x in [2048, 3072, 4096]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_dsa(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.DSA,
                                        None, 'mode')
        for x in [2048, 3072]:
            key_spec.bit_length = x
            self.assertTrue(self.secret_store.generate_supports(key_spec))

    def test_generate_supports_with_invalid_alg(self):
        key_spec = secret_store.KeySpec('invalid_alg', 56, 'mode')
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
            enums.CryptographicAlgorithm.AES,
            128)

    def test_generate_symmetric_key_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        return_value = self.secret_store.generate_symmetric_key(key_spec)
        expected = {kss.KMIPSecretStore.KEY_UUID:
                    self.symmetric_key_uuid}

        self.assertEqual(expected, return_value)

    def test_generate_symmetric_key_server_error_occurs(self):
        self.secret_store.client.create.side_effect = Exception

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
        self.secret_store.client.open.side_effect = Exception

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
            enums.CryptographicAlgorithm.RSA,
            2048)

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
        self.secret_store.client.create_key_pair.side_effect = Exception

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
            secret_store.SecretAlgorithmNotSupportedException,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_check_for_passphrase(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA,
                                        2048, 'mode', 'passphrase')
        self.assertRaises(
            kss.KMIPSecretStoreActionNotSupported,
            self.secret_store.generate_asymmetric_key,
            key_spec)

    def test_generate_asymmetric_key_error_opening_connection(self):
        self.secret_store.client.open.side_effect = Exception

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
        sym_key = utils.get_symmetric_key()
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            sym_key,
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            objects.SymmetricKey(
                enums.CryptographicAlgorithm.AES,
                128,
                base64.b64decode(utils.get_symmetric_key())))

    def test_store_symmetric_secret_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')
        sym_key = utils.get_symmetric_key()
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            sym_key,
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(expected, return_value)

    def test_store_passphrase_secret_assert_called(self):
        key_spec = secret_store.KeySpec(None, None, None)
        passphrase = base64.b64encode(b"supersecretpassphrase")
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.PASSPHRASE,
                                            passphrase,
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            objects.SecretData(
                base64.b64decode(passphrase),
                enums.SecretDataType.PASSWORD))

    def test_store_passphrase_secret_return_value(self):
        key_spec = secret_store.KeySpec(None, None, None)
        passphrase = b"supersecretpassphrase"
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.PASSPHRASE,
                                            base64.b64encode(passphrase),
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(expected, return_value)

    def test_store_opaque_secret_assert_called(self):
        key_spec = secret_store.KeySpec(None, None, None)
        opaque = base64.b64encode(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.OPAQUE,
                                            opaque,
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            objects.OpaqueObject(
                base64.b64decode(opaque),
                enums.OpaqueDataType.NONE))

    def test_store_opaque_secret_return_value(self):
        key_spec = secret_store.KeySpec(None, None, None)
        opaque = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        secret_dto = secret_store.SecretDTO(secret_store.SecretType.OPAQUE,
                                            base64.b64encode(opaque),
                                            key_spec,
                                            'content_type',
                                            transport_key=None)
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(expected, return_value)

    @utils.parameterized_dataset({
        'private_pkcs8': [secret_store.SecretType.PRIVATE,
                          keys.get_private_key_pem(),
                          enums.ObjectType.PRIVATE_KEY,
                          keys.get_private_key_der(),
                          False],
        'private_pkcs1': [secret_store.SecretType.PRIVATE,
                          keys.get_private_key_pem(),
                          enums.ObjectType.PRIVATE_KEY,
                          kss.get_private_key_der_pkcs1(
                              keys.get_private_key_pem()),
                          True],
        'public_pkcs8': [secret_store.SecretType.PUBLIC,
                         keys.get_public_key_pem(),
                         enums.ObjectType.PUBLIC_KEY,
                         keys.get_public_key_der(),
                         False],
        'public_pkcs1': [secret_store.SecretType.PUBLIC,
                         keys.get_public_key_pem(),
                         enums.ObjectType.PUBLIC_KEY,
                         kss.get_public_key_der_pkcs1(
                             keys.get_public_key_pem()),
                         True],
    })
    def test_store_asymmetric_key_secret_assert_called(self,
                                                       barbican_type,
                                                       barbican_key,
                                                       kmip_type,
                                                       kmip_key,
                                                       pkcs1_only):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA, 2048)
        secret_value = base64.b64encode(barbican_key)
        secret_dto = secret_store.SecretDTO(barbican_type,
                                            secret_value,
                                            key_spec,
                                            'content_type')
        self.secret_store.pkcs1_only = pkcs1_only
        self.secret_store.store_secret(secret_dto)
        secret_value = base64.b64decode(secret_value)
        if not pkcs1_only:
            secret_value = translations.convert_pem_to_der(
                secret_value,
                barbican_type)
        if kmip_type == enums.ObjectType.PUBLIC_KEY:
            if pkcs1_only:
                secret_value = kss.get_public_key_der_pkcs1(secret_value)
            secret = objects.PublicKey(
                enums.CryptographicAlgorithm.RSA,
                2048,
                secret_value,
                enums.KeyFormatType.X_509)
        else:
            if pkcs1_only:
                secret_value = kss.get_private_key_der_pkcs1(secret_value)
            secret = objects.PrivateKey(
                enums.CryptographicAlgorithm.RSA,
                2048,
                secret_value,
                enums.KeyFormatType.PKCS_8)

        self.secret_store.client.register.assert_called_once_with(secret)

    @utils.parameterized_dataset({
        'private_pkcs8': [secret_store.SecretType.PRIVATE,
                          keys.get_private_key_pem(),
                          False],
        'private_pkcs1': [secret_store.SecretType.PRIVATE,
                          keys.get_private_key_pem(),
                          True],
        'public_pkcs8': [secret_store.SecretType.PUBLIC,
                         keys.get_public_key_pem(),
                         False],
        'public_pkcs1': [secret_store.SecretType.PUBLIC,
                         keys.get_public_key_pem(),
                         True],
    })
    def test_store_asymmetric_key_secret_return_value(self,
                                                      barbican_type,
                                                      barbican_key,
                                                      pkcs1_only):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA, 2048)
        secret_dto = secret_store.SecretDTO(barbican_type,
                                            base64.b64encode(barbican_key),
                                            key_spec,
                                            'content_type')
        self.secret_store.pkcs1_only = pkcs1_only
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(expected, return_value)

    @utils.parameterized_dataset({
        'rsa': [secret_store.KeyAlgorithm.RSA, 2048],
        'no_key_spec': [None, None]
    })
    def test_store_certificate_secret_assert_called(
            self, algorithm, bit_length):
        key_spec = secret_store.KeySpec(algorithm, bit_length)
        certificate_value = base64.b64encode(keys.get_certificate_pem())
        secret_dto = secret_store.SecretDTO(
            secret_store.SecretType.CERTIFICATE,
            certificate_value,
            key_spec,
            'content_type')
        self.secret_store.store_secret(secret_dto)
        self.secret_store.client.register.assert_called_once_with(
            objects.X509Certificate(translations.convert_pem_to_der(
                base64.b64decode(certificate_value),
                secret_store.SecretType.CERTIFICATE)))

    def test_store_certificate_secret_return_value(self):
        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.RSA, 2048)
        secret_dto = secret_store.SecretDTO(
            secret_store.SecretType.CERTIFICATE,
            base64.b64encode(keys.get_certificate_pem()),
            key_spec,
            'content_type')
        return_value = self.secret_store.store_secret(secret_dto)
        expected = {kss.KMIPSecretStore.KEY_UUID: 'uuid'}

        self.assertEqual(expected, return_value)

    def test_store_secret_server_error_occurs(self):
        self.secret_store.client.register.side_effect = Exception

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')

        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            utils.get_symmetric_key(),
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

    def test_store_secret_error_opening_connection(self):
        self.secret_store.client.open.side_effect = Exception

        key_spec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES,
                                        128, 'mode')

        secret_dto = secret_store.SecretDTO(secret_store.SecretType.SYMMETRIC,
                                            utils.get_symmetric_key(),
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
                      utils.get_symmetric_key(),
                      False],
        'hmac_sha1': [get_sample_symmetric_key(
                      algorithm=enums.CryptographicAlgorithm.HMAC_SHA1),
                      secret_store.SecretType.SYMMETRIC,
                      utils.get_symmetric_key(),
                      False],
        'hmac_sha256': [get_sample_symmetric_key(
                        algorithm=enums.CryptographicAlgorithm.HMAC_SHA256),
                        secret_store.SecretType.SYMMETRIC,
                        utils.get_symmetric_key(),
                        False],
        'hmac_sha384': [get_sample_symmetric_key(
                        algorithm=enums.CryptographicAlgorithm.HMAC_SHA384),
                        secret_store.SecretType.SYMMETRIC,
                        utils.get_symmetric_key(),
                        False],
        'hmac_sha512': [get_sample_symmetric_key(
                        algorithm=enums.CryptographicAlgorithm.HMAC_SHA512),
                        secret_store.SecretType.SYMMETRIC,
                        utils.get_symmetric_key(),
                        False],
        'triple_des': [get_sample_symmetric_key(
                       key_b64=utils.get_triple_des_key(),
                       key_length=192,
                       algorithm=enums.CryptographicAlgorithm.TRIPLE_DES),
                       secret_store.SecretType.SYMMETRIC,
                       utils.get_triple_des_key(),
                       False],
        'opaque': [get_sample_opaque_secret(),
                   secret_store.SecretType.OPAQUE,
                   utils.get_symmetric_key(),
                   False],
        'public_key': [get_sample_public_key(),
                       secret_store.SecretType.PUBLIC,
                       base64.b64encode(keys.get_public_key_pem()),
                       False],
        'public_key_pkcs1': [get_sample_public_key(pkcs1=True),
                             secret_store.SecretType.PUBLIC,
                             base64.b64encode(keys.get_public_key_pem()),
                             True],
        'private_key': [get_sample_private_key(),
                        secret_store.SecretType.PRIVATE,
                        base64.b64encode(keys.get_private_key_pem()),
                        False],
        'private_key_pkcs1': [get_sample_private_key(pkcs1=True),
                              secret_store.SecretType.PRIVATE,
                              base64.b64encode(keys.get_private_key_pem()),
                              True],
        'certificate': [get_sample_certificate(),
                        secret_store.SecretType.CERTIFICATE,
                        base64.b64encode(keys.get_certificate_pem()),
                        False]
    })
    def test_get_secret(self, kmip_secret, secret_type, expected_secret,
                        pkcs1_only):
        self.secret_store.pkcs1_only = pkcs1_only
        self.secret_store.client.get.return_value = kmip_secret
        uuid = utils.generate_test_uuid(0)
        metadata = {kss.KMIPSecretStore.KEY_UUID: uuid}
        secret_dto = self.secret_store.get_secret(secret_type, metadata)

        self.secret_store.client.get.assert_called_once_with(uuid)
        self.assertEqual(secret_store.SecretDTO, type(secret_dto))
        self.assertEqual(secret_type, secret_dto.type)
        self.assertEqual(expected_secret, secret_dto.secret)

    def test_get_secret_symmetric_return_value_invalid_key_material_type(self):
        invalid_secret = self.sample_secret
        invalid_secret.value = list('invalid')
        self.secret_store.client.get.return_value = invalid_secret

        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    def test_get_secret_symmetric_server_error_occurs(self):
        self.secret_store.client.get.side_effect = Exception
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    def test_get_secret_symmetric_error_opening_connection(self):
        self.secret_store.client.open.side_effect = Exception

        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.get_secret,
            self.symmetric_type, metadata)

    # ---------------- TEST DELETE -------------------------------------------

    def test_delete_with_null_metadata_values(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: None}
        self.assertIsNone(self.secret_store.delete_secret(metadata))

    def test_delete_secret_assert_called(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.secret_store.delete_secret(metadata)
        self.secret_store.client.destroy.assert_called_once_with(
            self.symmetric_key_uuid)

    def test_delete_secret_return_value(self):
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        return_value = self.secret_store.delete_secret(metadata)
        self.assertIsNone(return_value)

    def test_delete_secret_server_error_occurs(self):
        self.secret_store.client.destroy.side_effect = Exception
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.delete_secret,
            metadata)

    def test_delete_secret_error_opening_connection(self):
        self.secret_store.client.open.side_effect = Exception
        metadata = {kss.KMIPSecretStore.KEY_UUID: self.symmetric_key_uuid}
        self.assertRaises(
            secret_store.SecretGeneralException,
            self.secret_store.delete_secret,
            metadata)

    # -------------- TEST HELPER FUNCTIONS -----------------------------------

    def test_credential(self):
        actual_credential = self.secret_store.credential

        self.assertEqual(
            self.expected_username,
            actual_credential.credential_value.username)
        self.assertEqual(
            self.expected_password,
            actual_credential.credential_value.password)

    def test_credential_None(self):
        CONF = kss.CONF
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
            CONF = kss.CONF
            CONF.kmip_plugin.keyfile = '/some/path'
            kss.KMIPSecretStore(CONF)
            self.assertEqual(1, len(m.mock_calls))

    def test_get_plugin_name(self):
        CONF = kss.CONF
        CONF.kmip_plugin.plugin_name = "Test KMIP Plugin"
        secret_store = kss.KMIPSecretStore(CONF)
        self.assertEqual("Test KMIP Plugin", secret_store.get_plugin_name())
