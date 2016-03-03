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

import mock
import six

from barbican.model import models
from barbican.plugin.crypto import crypto as plugin_import
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto import pkcs11
from barbican.tests import utils

if six.PY3:
    long = int


def generate_random_effect(length, session):
    return b'0' * length


class WhenTestingP11CryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingP11CryptoPlugin, self).setUp()

        self.pkcs11 = mock.Mock()
        self.pkcs11.get_session.return_value = long(1)
        self.pkcs11.return_session.return_value = None
        self.pkcs11.generate_random.side_effect = generate_random_effect
        self.pkcs11.get_key_handle.return_value = long(2)
        self.pkcs11.encrypt.return_value = {'iv': b'0', 'ct': b'0'}
        self.pkcs11.decrypt.return_value = b'0'
        self.pkcs11.generate_key.return_value = long(3)
        self.pkcs11.wrap_key.return_value = {'iv': b'1', 'wrapped_key': b'1'}
        self.pkcs11.unwrap_key.return_value = long(4)
        self.pkcs11.compute_hmac.return_value = b'1'
        self.pkcs11.verify_hmac.return_value = None
        self.pkcs11.destroy_object.return_value = None

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.p11_crypto_plugin.mkek_label = 'mkek_label'
        self.cfg_mock.p11_crypto_plugin.hmac_label = 'hmac_label'
        self.cfg_mock.p11_crypto_plugin.mkek_length = 32
        self.cfg_mock.p11_crypto_plugin.slot_id = 1
        self.cfg_mock.p11_crypto_plugin.rw_session = True
        self.cfg_mock.p11_crypto_plugin.pkek_length = 32
        self.cfg_mock.p11_crypto_plugin.pkek_cache_ttl = 900
        self.cfg_mock.p11_crypto_plugin.pkek_cache_limit = 10
        self.cfg_mock.p11_crypto_plugin.algorithm = 'CKM_AES_GCM'

        self.plugin = p11_crypto.P11CryptoPlugin(
            conf=self.cfg_mock, pkcs11=self.pkcs11
        )

    def test_invalid_library_path(self):
        cfg = self.cfg_mock.p11_crypto_plugin
        cfg.library_path = None
        self.assertRaises(ValueError, p11_crypto.P11CryptoPlugin,
                          conf=self.cfg_mock, pkcs11=self.pkcs11)

    def test_bind_kek_metadata_without_existing_key(self):
        kek_datum = models.KEKDatum()
        dto = plugin_import.KEKMetaDTO(kek_datum)
        dto = self.plugin.bind_kek_metadata(dto)

        self.assertEqual(dto.algorithm, 'AES')
        self.assertEqual(dto.bit_length, 256)
        self.assertEqual(dto.mode, 'CBC')

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.generate_key.call_count, 1)
        self.assertEqual(self.pkcs11.wrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.compute_hmac.call_count, 1)

    def test_bind_kek_metadata_with_existing_key(self):
        kek_datum = models.KEKDatum()
        dto = plugin_import.KEKMetaDTO(kek_datum)
        dto.plugin_meta = '{}'
        dto = self.plugin.bind_kek_metadata(dto)

        self.assertEqual(self.pkcs11.generate_key.call_count, 0)
        self.assertEqual(self.pkcs11.wrap_key.call_count, 0)
        self.assertEqual(self.pkcs11.compute_hmac.call_count, 0)

    def test_encrypt(self):
        payload = b'test payload'
        encrypt_dto = plugin_import.EncryptDTO(payload)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        response_dto = self.plugin.encrypt(encrypt_dto,
                                           kek_meta,
                                           mock.MagicMock())

        self.assertEqual(response_dto.cypher_text, b'0')
        self.assertIn('iv', response_dto.kek_meta_extended)

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.get_session.call_count, 2)
        self.assertEqual(self.pkcs11.verify_hmac.call_count, 1)
        self.assertEqual(self.pkcs11.unwrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.encrypt.call_count, 1)
        self.assertEqual(self.pkcs11.return_session.call_count, 1)

    def test_encrypt_bad_session(self):
        self.pkcs11.get_session.return_value = mock.DEFAULT
        self.pkcs11.get_session.side_effect = pkcs11.P11CryptoPluginException(
            'Testing error handling'
        )
        payload = b'test payload'
        encrypt_dto = plugin_import.EncryptDTO(payload)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        self.assertRaises(pkcs11.P11CryptoPluginException,
                          self.plugin.encrypt,
                          encrypt_dto,
                          kek_meta,
                          mock.MagicMock())

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.get_session.call_count, 2)
        self.assertEqual(self.pkcs11.verify_hmac.call_count, 1)
        self.assertEqual(self.pkcs11.unwrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.encrypt.call_count, 0)
        self.assertEqual(self.pkcs11.return_session.call_count, 0)

    def test_decrypt(self):
        ct = b'ctct'
        kek_meta_extended = '{"iv":"AAAA"}'
        decrypt_dto = plugin_import.DecryptDTO(ct)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        pt = self.plugin.decrypt(decrypt_dto,
                                 kek_meta,
                                 kek_meta_extended,
                                 mock.MagicMock())

        self.assertEqual(pt, b'0')

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.get_session.call_count, 2)
        self.assertEqual(self.pkcs11.verify_hmac.call_count, 1)
        self.assertEqual(self.pkcs11.unwrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.decrypt.call_count, 1)
        self.assertEqual(self.pkcs11.return_session.call_count, 1)

    def test_decrypt_bad_session(self):
        self.pkcs11.get_session.return_value = mock.DEFAULT
        self.pkcs11.get_session.side_effect = pkcs11.P11CryptoPluginException(
            'Testing error handling'
        )
        ct = b'ctct'
        kek_meta_extended = '{"iv":"AAAA"}'
        decrypt_dto = plugin_import.DecryptDTO(ct)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        self.assertRaises(pkcs11.P11CryptoPluginException,
                          self.plugin.decrypt,
                          decrypt_dto,
                          kek_meta,
                          kek_meta_extended,
                          mock.MagicMock())

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.get_session.call_count, 2)
        self.assertEqual(self.pkcs11.verify_hmac.call_count, 1)
        self.assertEqual(self.pkcs11.unwrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.decrypt.call_count, 0)
        self.assertEqual(self.pkcs11.return_session.call_count, 0)

    def test_generate_symmetric(self):
        secret = models.Secret()
        secret.bit_length = 128
        secret.algorithm = 'AES'
        generate_dto = plugin_import.GenerateDTO(
            secret.algorithm,
            secret.bit_length,
            None, None)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        response_dto = self.plugin.generate_symmetric(generate_dto,
                                                      kek_meta,
                                                      mock.MagicMock())

        self.assertEqual(response_dto.cypher_text, b'0')
        self.assertIn('iv', response_dto.kek_meta_extended)

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)
        self.assertEqual(self.pkcs11.get_session.call_count, 2)
        self.assertEqual(self.pkcs11.generate_random.call_count, 1)
        self.assertEqual(self.pkcs11.verify_hmac.call_count, 1)
        self.assertEqual(self.pkcs11.unwrap_key.call_count, 1)
        self.assertEqual(self.pkcs11.encrypt.call_count, 1)
        self.assertEqual(self.pkcs11.return_session.call_count, 1)

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

    def test_does_not_supports_asymmetric_key_generation(self):
        self.assertFalse(
            self.plugin.supports(
                plugin_import.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION
            )
        )

    def test_does_not_support_unknown_type(self):
        self.assertFalse(
            self.plugin.supports('SOMETHING_RANDOM')
        )

    def test_missing_mkek(self):
        self.pkcs11.get_key_handle.return_value = None
        self.assertRaises(pkcs11.P11CryptoKeyHandleException,
                          self.plugin._get_master_key,
                          'bad_key_label')

    def test_cached_kek_expired(self):
        self.plugin.pkek_cache['expired_kek'] = p11_crypto.CachedKEK(4, 0)
        self.assertIsNone(self.plugin._pkek_cache_get('expired_kek'))

    def test_generate_mkek(self):
        self.pkcs11.get_key_handle.return_value = None

        mkek = self.plugin._generate_mkek(256, 'mkek_label_2')
        self.assertEqual(mkek, 3)

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 3)
        self.assertEqual(self.pkcs11.generate_key.call_count, 1)

    def test_cached_generate_mkek(self):
        self.assertRaises(pkcs11.P11CryptoPluginKeyException,
                          self.plugin._generate_mkek, 256, 'mkek_label')
        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)

    def test_existing_generate_mkek(self):
        self.assertRaises(pkcs11.P11CryptoPluginKeyException,
                          self.plugin._generate_mkek, 256, 'mkek2_label')
        self.assertEqual(self.pkcs11.get_key_handle.call_count, 3)

    def test_generate_mkhk(self):
        self.pkcs11.get_key_handle.return_value = None

        mkhk = self.plugin._generate_mkhk(256, 'mkhk_label_2')
        self.assertEqual(mkhk, 3)

        self.assertEqual(self.pkcs11.get_key_handle.call_count, 3)
        self.assertEqual(self.pkcs11.generate_key.call_count, 1)

    def test_cached_generate_mkhk(self):
        self.assertRaises(pkcs11.P11CryptoPluginKeyException,
                          self.plugin._generate_mkhk, 256, 'hmac_label')
        self.assertEqual(self.pkcs11.get_key_handle.call_count, 2)

    def test_existing_generate_mkhk(self):
        self.assertRaises(pkcs11.P11CryptoPluginKeyException,
                          self.plugin._generate_mkhk, 256, 'mkhk2_label')
        self.assertEqual(self.pkcs11.get_key_handle.call_count, 3)

    def test_create_pkcs11(self):
        def _generate_random(session, buf, length):
            ffi.buffer(buf)[:] = b'0' * length
            return pkcs11.CKR_OK
        lib = mock.Mock()
        lib.C_Initialize.return_value = pkcs11.CKR_OK
        lib.C_OpenSession.return_value = pkcs11.CKR_OK
        lib.C_CloseSession.return_value = pkcs11.CKR_OK
        lib.C_GetSessionInfo.return_value = pkcs11.CKR_OK
        lib.C_Login.return_value = pkcs11.CKR_OK
        lib.C_GenerateRandom.side_effect = _generate_random
        ffi = pkcs11.build_ffi()
        setattr(ffi, 'dlopen', lambda x: lib)

        p11 = self.plugin._create_pkcs11(self.cfg_mock.p11_crypto_plugin, ffi)
        self.assertIsInstance(p11, pkcs11.PKCS11)
