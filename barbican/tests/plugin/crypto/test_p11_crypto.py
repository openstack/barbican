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

import builtins
from unittest import mock

from barbican.common import exception as ex
from barbican.model import models
from barbican.plugin.crypto import base as plugin_import
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto import pkcs11
from barbican.tests import utils


def generate_random_effect(length, session):
    return b'0' * length


class WhenTestingP11CryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingP11CryptoPlugin, self).setUp()

        self.pkcs11 = mock.Mock()
        self.pkcs11.get_session.return_value = int(1)
        self.pkcs11.return_session.return_value = None
        self.pkcs11.generate_random.side_effect = generate_random_effect
        self.pkcs11.get_key_handle.return_value = int(2)
        self.pkcs11.encrypt.return_value = {'iv': b'0', 'ct': b'0'}
        self.pkcs11.decrypt.return_value = b'0'
        self.pkcs11.generate_key.return_value = int(3)
        self.pkcs11.wrap_key.return_value = {'iv': b'1', 'wrapped_key': b'1'}
        self.pkcs11.unwrap_key.return_value = int(4)
        self.pkcs11.compute_hmac.return_value = b'1'
        self.pkcs11.verify_hmac.return_value = None
        self.pkcs11.destroy_object.return_value = None
        self.pkcs11.finalize.return_value = None

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.p11_crypto_plugin.mkek_label = 'mkek_label'
        self.cfg_mock.p11_crypto_plugin.hmac_label = 'hmac_label'
        self.cfg_mock.p11_crypto_plugin.mkek_length = 32
        self.cfg_mock.p11_crypto_plugin.slot_id = 1
        self.cfg_mock.p11_crypto_plugin.token_serial_number = None
        self.cfg_mock.p11_crypto_plugin.token_label = None
        self.cfg_mock.p11_crypto_plugin.token_labels = None
        self.cfg_mock.p11_crypto_plugin.rw_session = True
        self.cfg_mock.p11_crypto_plugin.pkek_length = 32
        self.cfg_mock.p11_crypto_plugin.pkek_cache_ttl = 900
        self.cfg_mock.p11_crypto_plugin.pkek_cache_limit = 10
        self.cfg_mock.p11_crypto_plugin.encryption_mechanism = 'CKM_AES_CBC'
        self.cfg_mock.p11_crypto_plugin.seed_file = ''
        self.cfg_mock.p11_crypto_plugin.seed_length = 32
        self.cfg_mock.p11_crypto_plugin.hmac_keywrap_mechanism = \
            'CKM_SHA256_HMAC'

        self.plugin_name = 'Test PKCS11 plugin'
        self.cfg_mock.p11_crypto_plugin.plugin_name = self.plugin_name

        self.plugin = p11_crypto.P11CryptoPlugin(
            conf=self.cfg_mock,
            pkcs11=self.pkcs11
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

        self.assertEqual('AES', dto.algorithm)
        self.assertEqual(256, dto.bit_length)
        self.assertEqual('CBC', dto.mode)

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(1, self.pkcs11.generate_key.call_count)
        self.assertEqual(1, self.pkcs11.wrap_key.call_count)
        self.assertEqual(1, self.pkcs11.compute_hmac.call_count)

    def test_bind_kek_metadata_with_existing_key(self):
        kek_datum = models.KEKDatum()
        dto = plugin_import.KEKMetaDTO(kek_datum)
        dto.plugin_meta = '{}'
        dto = self.plugin.bind_kek_metadata(dto)

        self.assertEqual(0, self.pkcs11.generate_key.call_count)
        self.assertEqual(0, self.pkcs11.wrap_key.call_count)
        self.assertEqual(0, self.pkcs11.compute_hmac.call_count)

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

        self.assertEqual(b'0', response_dto.cypher_text)
        self.assertIn('iv', response_dto.kek_meta_extended)

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(2, self.pkcs11.get_session.call_count)
        self.assertEqual(1, self.pkcs11.verify_hmac.call_count)
        self.assertEqual(1, self.pkcs11.unwrap_key.call_count)
        self.assertEqual(1, self.pkcs11.encrypt.call_count)
        self.assertEqual(1, self.pkcs11.return_session.call_count)

    def test_encrypt_bad_session(self):
        self.pkcs11.get_session.return_value = mock.DEFAULT
        self.pkcs11.get_session.side_effect = ex.P11CryptoPluginException(
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
        self.assertRaises(ex.P11CryptoPluginException,
                          self.plugin._encrypt,
                          encrypt_dto,
                          kek_meta,
                          mock.MagicMock())

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(2, self.pkcs11.get_session.call_count)
        self.assertEqual(1, self.pkcs11.verify_hmac.call_count)
        self.assertEqual(1, self.pkcs11.unwrap_key.call_count)
        self.assertEqual(0, self.pkcs11.encrypt.call_count)
        self.assertEqual(0, self.pkcs11.return_session.call_count)

    def test_decrypt(self):
        ct = b'ctct'
        kek_meta_extended = '{"iv":"AAAA","mechanism":"CKM_AES_CBC"}'
        decrypt_dto = plugin_import.DecryptDTO(ct)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "c2VjcmV0a2V5BwcHBwcHBw==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        pt = self.plugin.decrypt(decrypt_dto,
                                 kek_meta,
                                 kek_meta_extended,
                                 mock.MagicMock())

        self.assertEqual(b'0', pt)

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(2, self.pkcs11.get_session.call_count)
        self.assertEqual(1, self.pkcs11.verify_hmac.call_count)
        self.assertEqual(1, self.pkcs11.unwrap_key.call_count)
        self.assertEqual(1, self.pkcs11.decrypt.call_count)
        self.assertEqual(1, self.pkcs11.return_session.call_count)

    def test_decrypt_bad_session(self):
        self.pkcs11.get_session.return_value = mock.DEFAULT
        self.pkcs11.get_session.side_effect = ex.P11CryptoPluginException(
            'Testing error handling'
        )
        ct = b'ctct'
        kek_meta_extended = '{"iv":"AAAA","mechanism":"CKM_AES_CBC"}'
        decrypt_dto = plugin_import.DecryptDTO(ct)
        kek_meta = mock.MagicMock()
        kek_meta.kek_label = 'pkek'
        kek_meta.plugin_meta = ('{"iv": "iv==",'
                                '"hmac": "hmac",'
                                '"wrapped_key": "wrappedkey==",'
                                '"mkek_label": "mkek_label",'
                                '"hmac_label": "hmac_label"}')
        self.assertRaises(ex.P11CryptoPluginException,
                          self.plugin._decrypt,
                          decrypt_dto,
                          kek_meta,
                          kek_meta_extended,
                          mock.MagicMock())

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(2, self.pkcs11.get_session.call_count)
        self.assertEqual(1, self.pkcs11.verify_hmac.call_count)
        self.assertEqual(1, self.pkcs11.unwrap_key.call_count)
        self.assertEqual(0, self.pkcs11.decrypt.call_count)
        self.assertEqual(0, self.pkcs11.return_session.call_count)

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

        self.assertEqual(b'0', response_dto.cypher_text)
        self.assertIn('iv', response_dto.kek_meta_extended)

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(2, self.pkcs11.get_session.call_count)
        self.assertEqual(1, self.pkcs11.generate_random.call_count)
        self.assertEqual(1, self.pkcs11.verify_hmac.call_count)
        self.assertEqual(1, self.pkcs11.unwrap_key.call_count)
        self.assertEqual(1, self.pkcs11.encrypt.call_count)
        self.assertEqual(1, self.pkcs11.return_session.call_count)

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
        self.assertRaises(ex.P11CryptoKeyHandleException,
                          self.plugin._get_master_key,
                          self.plugin.mkek_key_type,
                          'bad_key_label')

    def test_cached_kek_expired(self):
        self.plugin.pkek_cache['expired_kek'] = p11_crypto.CachedKEK(4, 0)
        self.assertIsNone(self.plugin._pkek_cache_get('expired_kek'))

    def test_create_pkcs11(self):
        def _generate_random(session, buf, length):
            ffi.buffer(buf)[:] = b'0' * length
            return pkcs11.CKR_OK
        lib = mock.Mock()
        lib.C_Initialize.return_value = pkcs11.CKR_OK
        lib.C_GetSlotList.return_value = pkcs11.CKR_OK
        lib.C_GetTokenInfo.return_value = pkcs11.CKR_OK
        lib.C_OpenSession.return_value = pkcs11.CKR_OK
        lib.C_CloseSession.return_value = pkcs11.CKR_OK
        lib.C_GetSessionInfo.return_value = pkcs11.CKR_OK
        lib.C_Login.return_value = pkcs11.CKR_OK
        lib.C_GenerateRandom.side_effect = _generate_random
        lib.C_SeedRandom.return_value = pkcs11.CKR_OK
        ffi = pkcs11.build_ffi()
        setattr(ffi, 'dlopen', lambda x: lib)

        p11 = self.plugin._create_pkcs11(ffi)
        self.assertIsInstance(p11, pkcs11.PKCS11)

        # test for when plugin_conf.seed_file is not None
        self.plugin.seed_file = 'seed_file'
        d = '01234567' * 4
        mo = mock.mock_open(read_data=d)

        with mock.patch(builtins.__name__ + '.open',
                        mo,
                        create=True):
            p11 = self.plugin._create_pkcs11(ffi)

        self.assertIsInstance(p11, pkcs11.PKCS11)
        mo.assert_called_once_with('seed_file', 'rb')
        calls = [mock.call('seed_file', 'rb'),
                 mock.call().__enter__(),
                 mock.call().read(32),
                 mock.call().__exit__(None, None, None)]
        self.assertEqual(mo.mock_calls, calls)
        lib.C_SeedRandom.assert_called_once_with(mock.ANY, mock.ANY, 32)
        self.cfg_mock.p11_crypto_plugin.seed_file = ''

    def test_call_pkcs11_with_token_error(self):
        self.plugin._encrypt = mock.Mock()
        self.plugin._encrypt.side_effect = [ex.P11CryptoTokenException(
            'Testing error handling'
        ),
            'test payload']
        self.plugin._reinitialize_pkcs11 = mock.Mock()
        self.plugin._reinitialize_pkcs11.return_value = mock.DEFAULT

        self.plugin.encrypt(mock.MagicMock(), mock.MagicMock(),
                            mock.MagicMock())

        self.assertEqual(2, self.pkcs11.get_key_handle.call_count)
        self.assertEqual(1, self.pkcs11.get_session.call_count)
        self.assertEqual(0, self.pkcs11.return_session.call_count)
        self.assertEqual(2, self.plugin._encrypt.call_count)

    def test_reinitialize_pkcs11(self):
        pkcs11 = self.pkcs11
        self.plugin._create_pkcs11 = mock.Mock()
        self.plugin._create_pkcs11.return_value = pkcs11
        self.plugin._configure_object_cache = mock.Mock()
        self.plugin._configure_object_cache.return_value = mock.DEFAULT

        self.plugin._reinitialize_pkcs11()

        self.assertEqual(1, self.pkcs11.finalize.call_count)
        self.assertEqual(1, self.plugin._create_pkcs11.call_count)
        self.assertEqual(1, self.plugin._configure_object_cache.call_count)

    def test_get_plugin_name(self):
        self.assertEqual(self.plugin_name, self.plugin.get_plugin_name())
