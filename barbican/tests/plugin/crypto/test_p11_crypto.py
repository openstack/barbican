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
import json

import mock

from barbican.model import models
from barbican.plugin.crypto import crypto as plugin_import
from barbican.plugin.crypto import p11_crypto
from barbican.tests import utils


def write_random_first_byte(session, buf, length):
    buf[0] = 1
    return p11_crypto.CKR_OK


class WhenTestingP11CryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingP11CryptoPlugin, self).setUp()

        self.lib = mock.Mock()
        self.lib.C_Initialize.return_value = p11_crypto.CKR_OK
        self.lib.C_OpenSession.return_value = p11_crypto.CKR_OK
        self.lib.C_CloseSession.return_value = p11_crypto.CKR_OK
        self.lib.C_FindObjectsInit.return_value = p11_crypto.CKR_OK
        self.lib.C_FindObjects.return_value = p11_crypto.CKR_OK
        self.lib.C_FindObjectsFinal.return_value = p11_crypto.CKR_OK
        self.lib.C_GenerateKey.return_value = p11_crypto.CKR_OK
        self.lib.C_Login.return_value = p11_crypto.CKR_OK
        self.lib.C_GenerateRandom.side_effect = write_random_first_byte
        self.ffi = p11_crypto._build_ffi()
        setattr(self.ffi, 'dlopen', lambda x: self.lib)

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.p11_crypto_plugin.mkek_label = "mkek"
        self.cfg_mock.p11_crypto_plugin.hmac_label = "hmac"
        self.cfg_mock.p11_crypto_plugin.mkek_length = 32
        self.plugin = p11_crypto.P11CryptoPlugin(
            ffi=self.ffi, conf=self.cfg_mock
        )

        self.test_session = self.plugin._create_working_session()

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
            return p11_crypto.CKR_OK

        self.lib.C_FindObjects.side_effect = two_keys
        self.assertRaises(
            p11_crypto.P11CryptoPluginKeyException,
            self.plugin._get_key_handle,
            'mylabel',
            self.test_session
        )

    def test_get_key_handle_with_no_keys(self):
        result = self.plugin._get_key_handle('mylabel', self.test_session)
        self.assertIsNone(result)

    def test_get_key_handle_with_one_key(self):
        def one_key(session, object_handle_ptr, length, returned_count):
            object_handle_ptr[0] = 50
            returned_count[0] = 1
            return p11_crypto.CKR_OK

        self.lib.C_FindObjects.side_effect = one_key

        key = self.plugin._get_key_handle('mylabel', self.test_session)
        self.assertEqual(key, 50)

    def test_encrypt(self):
        payload = 'encrypt me!!'
        self.lib.C_EncryptInit.return_value = p11_crypto.CKR_OK
        self.lib.C_Encrypt.return_value = p11_crypto.CKR_OK
        encrypt_dto = plugin_import.EncryptDTO(payload)
        with mock.patch.object(self.plugin, '_unwrap_key') as unwrap_key_mock:
            unwrap_key_mock.return_value = 'unwrapped_key'
            response_dto = self.plugin.encrypt(encrypt_dto,
                                               mock.MagicMock(),
                                               mock.MagicMock())

            self.assertEqual(self.lib.C_Encrypt.call_count, 1)
            self.assertEqual(response_dto.cypher_text, b"\x00" * 32)

    def test_decrypt(self):
        def c_decrypt(session, ct, ctlen, pt, ptlen):
            pt[ptlen[0] - 1] = 1
            return p11_crypto.CKR_OK

        self.lib.C_Decrypt.side_effect = c_decrypt
        self.lib.C_DecryptInit.return_value = p11_crypto.CKR_OK
        ct = b"somedatasomedatasomedatasomedata"
        kek_meta_extended = '{"iv": "AQIDBAUGBwgJCgsMDQ4PEA=="}'
        decrypt_dto = plugin_import.DecryptDTO(ct)

        with mock.patch.object(self.plugin, '_unwrap_key') as unwrap_key_mock:
            unwrap_key_mock.return_value = 'unwrapped_key'
            self.plugin.decrypt(decrypt_dto,
                                mock.MagicMock(),
                                kek_meta_extended,
                                mock.MagicMock())
            self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_generate_wrapped_kek(self):
        self.lib.C_GenerateKey.return_value = p11_crypto.CKR_OK
        self.lib.C_WrapKey.return_value = p11_crypto.CKR_OK
        self.lib.C_SignInit.return_value = p11_crypto.CKR_OK
        self.lib.C_Sign.return_value = p11_crypto.CKR_OK
        self.plugin._generate_wrapped_kek("label", 32, self.test_session)
        self.assertEqual(self.lib.C_WrapKey.call_count, 1)
        self.assertEqual(self.lib.C_SignInit.call_count, 1)
        self.assertEqual(self.lib.C_Sign.call_count, 1)

    def test_bind_kek_metadata_without_existing_key(self):
        with mock.patch.object(self.plugin, '_generate_wrapped_kek'):
            kek_datum = models.KEKDatum()
            dto = plugin_import.KEKMetaDTO(kek_datum)
            dto = self.plugin.bind_kek_metadata(dto)
            self.assertEqual(dto.algorithm, "AES")
            self.assertEqual(dto.bit_length, 256)
            self.assertEqual(dto.mode, "CBC")

    def test_rng_self_test(self):
        with mock.patch.object(self.plugin, '_generate_random') as genmock:
            genmock.return_value = self.ffi.new("CK_BYTE[100]")
            self.assertRaises(
                p11_crypto.P11CryptoPluginException,
                self.plugin._perform_rng_self_test,
                self.test_session
            )

    def test_check_error(self):
        self.assertRaises(
            p11_crypto.P11CryptoPluginException, self.plugin._check_error, 1
        )

    def test_invalid_attribute(self):
        attrs = [p11_crypto.Attribute(0, object())]
        self.assertRaises(TypeError, self.plugin._build_attributes, attrs)

    def test_unwrap_key(self):
        plugin_meta = {
            'iv': base64.b64encode(b"\x00" * 16),
            'hmac': base64.b64encode(b"\x00" * 32),
            'wrapped_key': base64.b64encode(b"\x00" * 48),
            'mkek_label': 'mkek',
            'hmac_label': 'hmac',
        }
        self.lib.C_UnwrapKey.return_value = p11_crypto.CKR_OK
        self.lib.C_VerifyInit.return_value = p11_crypto.CKR_OK
        self.lib.C_Verify.return_value = p11_crypto.CKR_OK
        self.plugin._unwrap_key(json.dumps(plugin_meta), self.test_session)
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
