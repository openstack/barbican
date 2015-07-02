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

import base64

import mock

from barbican.model import models
from barbican.plugin.crypto import crypto as plugin_import
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto import pkcs11
from barbican.tests import utils


def write_random_first_byte(session, buf, length):
    buf[0] = 1
    return pkcs11.CKR_OK


class WhenTestingP11CryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingP11CryptoPlugin, self).setUp()

        self.lib = mock.Mock()
        self.lib.C_Initialize.return_value = pkcs11.CKR_OK
        self.lib.C_OpenSession.return_value = pkcs11.CKR_OK
        self.lib.C_CloseSession.return_value = pkcs11.CKR_OK
        self.lib.C_FindObjectsInit.return_value = pkcs11.CKR_OK
        self.lib.C_FindObjects.return_value = pkcs11.CKR_OK
        self.lib.C_FindObjectsFinal.return_value = pkcs11.CKR_OK
        self.lib.C_GenerateKey.return_value = pkcs11.CKR_OK
        self.lib.C_Login.return_value = pkcs11.CKR_OK
        self.lib.C_GenerateRandom.side_effect = write_random_first_byte
        self.ffi = pkcs11.build_ffi()
        setattr(self.ffi, 'dlopen', lambda x: self.lib)

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.p11_crypto_plugin.mkek_label = "mkek"
        self.cfg_mock.p11_crypto_plugin.hmac_label = "hmac"
        self.cfg_mock.p11_crypto_plugin.mkek_length = 32
        self.cfg_mock.p11_crypto_plugin.slot_id = 1
        with mock.patch.object(pkcs11.PKCS11, 'get_key_handle') as mocked:
            mocked.return_value = long(1)
            self.plugin = p11_crypto.P11CryptoPlugin(
                ffi=self.ffi, conf=self.cfg_mock
            )

        self.test_session = self.plugin.pkcs11.create_working_session()

    def test_generate_calls_generate_random(self):
        with mock.patch.object(self.plugin, 'encrypt') as encrypt_mock:
            encrypt_mock.return_value = None
            secret = models.Secret()
            secret.bit_length = 128
            secret.algorithm = "AES"
            generate_dto = plugin_import.GenerateDTO(
                secret.algorithm,
                secret.bit_length,
                None, None)
            self.plugin.generate_symmetric(
                generate_dto,
                mock.MagicMock(),
                mock.MagicMock()
            )
            self.assertEqual(self.lib.C_GenerateRandom.call_count, 2)

    def test_raises_error_with_no_library_path(self):
        m = mock.MagicMock()
        m.p11_crypto_plugin = mock.MagicMock(library_path=None)
        self.assertRaises(
            ValueError,
            p11_crypto.P11CryptoPlugin,
            m,
        )

    def test_raises_error_with_bad_library_path(self):
        m = mock.MagicMock()
        m.p11_crypto_plugin = mock.MagicMock(library_path="/dev/null")

        pykcs11error = Exception
        self.assertRaises(
            pykcs11error,
            p11_crypto.P11CryptoPlugin,
            m,
        )

    def test_get_key_handle_with_two_keys(self):
        def two_keys(session, object_handle_ptr, length, returned_count):
            returned_count[0] = 2
            return pkcs11.CKR_OK

        self.lib.C_FindObjects.side_effect = two_keys
        self.assertRaises(
            pkcs11.P11CryptoPluginKeyException,
            self.plugin.pkcs11.get_key_handle,
            'mylabel',
            self.test_session
        )

    def test_get_key_handle_with_no_keys(self):
        result = self.plugin.pkcs11.get_key_handle(
            'mylabel', self.test_session
        )
        self.assertIsNone(result)

    def test_get_key_handle_with_one_key(self):
        def one_key(session, object_handle_ptr, length, returned_count):
            object_handle_ptr[0] = 50
            returned_count[0] = 1
            return pkcs11.CKR_OK

        self.lib.C_FindObjects.side_effect = one_key

        key = self.plugin.pkcs11.get_key_handle('mylabel', self.test_session)
        self.assertEqual(key, 50)

    def test_encrypt(self):
        payload = 'encrypt me!!'
        self.lib.C_EncryptInit.return_value = pkcs11.CKR_OK
        self.lib.C_Encrypt.return_value = pkcs11.CKR_OK
        encrypt_dto = plugin_import.EncryptDTO(payload)
        kek_meta = mock.MagicMock()
        kek_meta.plugin_meta = ('{"iv":123,'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrapped_key",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        with mock.patch.object(self.plugin.pkcs11, 'unwrap_key') as key_mock:
            key_mock.return_value = 'unwrapped_key'
            response_dto = self.plugin.encrypt(encrypt_dto,
                                               kek_meta,
                                               mock.MagicMock())

            self.assertEqual(self.lib.C_Encrypt.call_count, 1)
            self.assertEqual(response_dto.cypher_text, b"\x00" * 32)

    def test_decrypt(self):
        def c_decrypt(session, ct, ctlen, pt, ptlen):
            pt[ptlen[0] - 1] = 1
            return pkcs11.CKR_OK

        self.lib.C_Decrypt.side_effect = c_decrypt
        self.lib.C_DecryptInit.return_value = pkcs11.CKR_OK
        ct = b"somedatasomedatasomedatasomedata"
        kek_meta_extended = '{"iv": "AQIDBAUGBwgJCgsMDQ4PEA=="}'
        decrypt_dto = plugin_import.DecryptDTO(ct)

        kek_meta = mock.MagicMock()
        kek_meta.plugin_meta = ('{"iv":123,'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrapped_key",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        with mock.patch.object(self.plugin.pkcs11, 'unwrap_key') as key_mock:
            key_mock.return_value = 'unwrapped_key'
            self.plugin.decrypt(decrypt_dto,
                                kek_meta,
                                kek_meta_extended,
                                mock.MagicMock())
            self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_generate_wrapped_kek(self):
        self.lib.C_GenerateKey.return_value = pkcs11.CKR_OK
        self.lib.C_WrapKey.return_value = pkcs11.CKR_OK
        self.lib.C_SignInit.return_value = pkcs11.CKR_OK
        self.lib.C_Sign.return_value = pkcs11.CKR_OK
        self.plugin.pkcs11.generate_wrapped_kek("label", 32, self.test_session)
        self.assertEqual(self.lib.C_WrapKey.call_count, 1)
        self.assertEqual(self.lib.C_SignInit.call_count, 1)
        self.assertEqual(self.lib.C_Sign.call_count, 1)

    def test_bind_kek_metadata_without_existing_key(self):
        with mock.patch.object(self.plugin.pkcs11, 'generate_wrapped_kek'):
            kek_datum = models.KEKDatum()
            dto = plugin_import.KEKMetaDTO(kek_datum)
            dto = self.plugin.bind_kek_metadata(dto)
            self.assertEqual(dto.algorithm, "AES")
            self.assertEqual(dto.bit_length, 256)
            self.assertEqual(dto.mode, "CBC")

    def test_rng_self_test(self):
        with mock.patch.object(
            self.plugin.pkcs11, 'generate_random'
        ) as genmock:
            genmock.return_value = self.ffi.new("CK_BYTE[100]")
            self.assertRaises(
                pkcs11.P11CryptoPluginException,
                self.plugin.pkcs11.perform_rng_self_test,
                self.test_session
            )

    def test_check_error(self):
        self.assertRaises(
            pkcs11.P11CryptoPluginException, self.plugin.pkcs11.check_error, 1
        )

    def test_invalid_attribute(self):
        attrs = [pkcs11.Attribute(0, object())]
        self.assertRaises(
            TypeError, self.plugin.pkcs11.build_attributes, attrs
        )

    def test_unwrap_key(self):
        plugin_meta = {
            'iv': base64.b64encode(b"\x00" * 16),
            'hmac': base64.b64encode(b"\x00" * 32),
            'wrapped_key': base64.b64encode(b"\x00" * 48),
            'mkek_label': 'mkek',
            'hmac_label': 'hmac',
        }
        self.lib.C_UnwrapKey.return_value = pkcs11.CKR_OK
        self.lib.C_VerifyInit.return_value = pkcs11.CKR_OK
        self.lib.C_Verify.return_value = pkcs11.CKR_OK

        self.plugin.pkcs11.unwrap_key(
            plugin_meta['iv'], plugin_meta['hmac'], plugin_meta['wrapped_key'],
            plugin_meta['mkek_label'], plugin_meta['hmac'], self.test_session
        )
        self.assertEqual(self.lib.C_UnwrapKey.call_count, 1)
        self.assertEqual(self.lib.C_Verify.call_count, 1)

    def test_generate_asymmetric_raises_error(self):
        self.assertRaises(NotImplementedError,
                          self.plugin.generate_asymmetric,
                          mock.MagicMock(),
                          mock.MagicMock(),
                          mock.MagicMock())

    def test_supports_encrypt_decrypt(self):
        self.assertTrue(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.ENCRYPT_DECRYPT
            )
        )

    def test_supports_symmetric_key_generation(self):
        self.assertTrue(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.SYMMETRIC_KEY_GENERATION
            )
        )

    def test_does_not_support_asymmetric_key_generation(self):
        self.assertFalse(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION
            )
        )

    def test_does_not_support_unknown_type(self):
        self.assertFalse(
            self.plugin.supports("SOMETHING_RANDOM")
        )

    def test_default_slot_id(self):
        with mock.patch.object(self.plugin.pkcs11, 'open_session') as mocked:
            def mocked_open_session(slot):
                self.assertEqual(1, slot)

            mocked.side_effect = mocked_open_session
            self.plugin.pkcs11.create_working_session()

    def test_configurable_slot_id(self):
        self.cfg_mock.p11_crypto_plugin.slot_id = 99
        with mock.patch.object(pkcs11.PKCS11, 'get_key_handle') as mocked:
            mocked.return_value = long(1)
            test_plugin = p11_crypto.P11CryptoPlugin(
                ffi=self.ffi, conf=self.cfg_mock
            )

        with mock.patch.object(test_plugin.pkcs11, 'open_session') as mocked:
            def mocked_open_session(slot):
                self.assertEqual(99, slot)

            mocked.side_effect = mocked_open_session
            test_plugin.pkcs11.create_working_session()

    def test_generate_mkek(self):
        mkek_label = 'mkek'
        mkek_length = 32
        mkek = self.plugin.pkcs11.generate_mkek(
            mkek_label, mkek_length, self.test_session
        )
        self.assertEqual(long(0), mkek)

    def test_generate_hmac_key(self):
        hmac_label = 'hmac'
        hmac = self.plugin.pkcs11.generate_hmac_key(
            hmac_label, self.test_session
        )
        self.assertEqual(long(0), hmac)

    def test_get_mkek_with_no_mkek(self):
        with mock.patch.object(pkcs11.PKCS11, 'get_key_handle') as mocked:
            mocked.return_value = None
            self.assertRaises(
                pkcs11.P11CryptoKeyHandleException,
                self.plugin.pkcs11.get_mkek,
                'mkek',
                self.test_session
            )

    def test_get_hmac_with_no_hmac(self):
        with mock.patch.object(pkcs11.PKCS11, 'get_key_handle') as mocked:
            mocked.return_value = None
            self.assertRaises(
                pkcs11.P11CryptoKeyHandleException,
                self.plugin.pkcs11.get_hmac_key,
                'hmac',
                self.test_session
            )
