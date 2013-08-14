# Copyright (c) 2013 Rackspace, Inc.
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

from Crypto import Random
from mock import MagicMock
from mock import patch
import unittest

from barbican.crypto.p11_crypto import P11CryptoPlugin
from barbican.crypto.p11_crypto import P11CryptoPluginKeyException
from barbican.crypto.p11_crypto import P11CryptoPluginException


class WhenTestingP11CryptoPlugin(unittest.TestCase):

    def setUp(self):
        self.p11_mock = MagicMock(CKR_OK=0, CKF_RW_SESSION='RW',
                                  name='PyKCS11 mock')
        self.patcher = patch('barbican.crypto.p11_crypto.PyKCS11',
                             new=self.p11_mock)
        self.patcher.start()
        self.pkcs11 = self.p11_mock.PyKCS11Lib()
        self.p11_mock.PyKCS11Error.return_value = Exception()
        self.pkcs11.lib.C_Initialize.return_value = self.p11_mock.CKR_OK
        self.cfg_mock = MagicMock(name='config mock')
        self.plugin = P11CryptoPlugin(self.cfg_mock)
        self.session = self.pkcs11.openSession()

    def tearDown(self):
        self.patcher.stop()

    def test_pad_binary_string(self):
        binary_string = b'some_binary_string'
        padded_string = (
            b'some_binary_string' +
            b'\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
        )
        self.assertEqual(self.plugin._pad(binary_string), padded_string)

    def test_pad_random_bytes(self):
        random_bytes = Random.get_random_bytes(10)
        padded_bytes = random_bytes + b'\x06\x06\x06\x06\x06\x06'
        self.assertEqual(self.plugin._pad(random_bytes), padded_bytes)

    def test_strip_padding_from_binary_string(self):
        binary_string = b'some_binary_string'
        padded_string = (
            b'some_binary_string' +
            b'\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
        )
        self.assertEqual(self.plugin._strip_pad(padded_string), binary_string)

    def test_strip_padding_from_random_bytes(self):
        random_bytes = Random.get_random_bytes(10)
        padded_bytes = random_bytes + b'\x06\x06\x06\x06\x06\x06'
        self.assertEqual(self.plugin._strip_pad(padded_bytes), random_bytes)

    def test_create_calls_generate_random(self):
        self.session.generateRandom.return_value = [1, 2, 3, 4, 5, 6, 7,
                                                    8, 9, 10, 11, 12, 13,
                                                    14, 15, 16, 17, 18, 19,
                                                    20, 21, 22, 23, 24, 25,
                                                    26, 27, 28, 29, 30, 31, 32]
        key = self.plugin.create("aes", 256)
        self.assertEqual(len(key), 32)
        self.session.generateRandom.assert_called_once_with(32)

    def test_create_errors_when_not_modulo_8(self):
        with self.assertRaises(ValueError):
            self.plugin.create("aes", 255)

    def test_create_errors_when_negative(self):
        with self.assertRaises(ValueError):
            self.plugin.create("aes", -128)

    def test_create_errors_when_zero(self):
        with self.assertRaises(ValueError):
            self.plugin.create("aes", 0)

    def test_create_errors_when_rand_length_is_not_as_requested(self):
        self.session.generateRandom.return_value = [1, 2, 3, 4, 5, 6, 7]
        with self.assertRaises(P11CryptoPluginException):
            self.plugin.create("aes", 192)

    def test_raises_error_with_no_library_path(self):
        mock = MagicMock()
        mock.p11_crypto_plugin = MagicMock(library_path=None)
        with self.assertRaises(ValueError):
            P11CryptoPlugin(mock)

    def test_init_builds_sessions_and_login(self):
        self.pkcs11.openSession.assert_any_call(1)
        self.pkcs11.openSession.login.assert_called_twice()
        self.pkcs11.openSession.assert_any_call(1, 'RW')
        self.session.login.assert_called_twice()

    def test_get_key_by_label_with_two_keys(self):
        self.session.findObjects.return_value = ['key1', 'key2']
        self.session.findObjects.assert_called_once()
        with self.assertRaises(P11CryptoPluginKeyException):
            self.plugin._get_key_by_label('mylabel')

    def test_get_key_by_label_with_one_key(self):
        key = 'key1'
        self.session.findObjects.return_value = [key]
        self.session.findObjects.assert_called_once()
        key_label = self.plugin._get_key_by_label('mylabel')
        self.assertEqual(key, key_label)

    def test_get_key_by_label_with_no_keys(self):
        self.session.findObjects.return_value = []
        self.session.findObjects.assert_called_once()
        result = self.plugin._get_key_by_label('mylabel')
        self.assertIsNone(result)

    def test_generate_iv_calls_generate_random(self):
        self.session.generateRandom.return_value = [1, 2, 3, 4, 5, 6, 7,
                                                    8, 9, 10, 11, 12, 13,
                                                    14, 15, 16]
        iv = self.plugin._generate_iv()
        self.assertEqual(len(iv), self.plugin.block_size)
        self.session.generateRandom.\
            assert_called_once_with(self.plugin.block_size)

    def test_generate_iv_with_invalid_response_size(self):
        self.session.generateRandom.return_value = [1, 2, 3, 4, 5, 6, 7]
        with self.assertRaises(P11CryptoPluginException):
            self.plugin._generate_iv()

    def test_build_gcm_params(self):
        class GCM_Mock(object):
            def __init__(self):
                self.pIv = None
                self.ulIvLen = None
                self.ulIvBits = None
                self.ulTagBits = None

        self.p11_mock.LowLevel.CK_AES_GCM_PARAMS.return_value = GCM_Mock()
        iv = b'sixteen_byte_iv_'
        gcm = self.plugin._build_gcm_params(iv)
        self.assertEqual(iv, gcm.pIv)
        self.assertEqual(len(iv), gcm.ulIvLen)
        self.assertEqual(len(iv) * 8, gcm.ulIvBits)
        self.assertEqual(128, gcm.ulIvBits)

    def test_encrypt(self):
        key = 'key1'
        payload = 'encrypt me!!'
        self.session.findObjects.return_value = [key]
        self.session.generateRandom.return_value = [1, 2, 3, 4, 5, 6, 7,
                                                    8, 9, 10, 11, 12, 13,
                                                    14, 15, 16]
        mech = MagicMock()
        self.p11_mock.Mechanism.return_value = mech
        self.session.encrypt.return_value = [1, 2, 3, 4, 5]
        cyphertext, kek_meta_extended = self.plugin.encrypt(payload,
                                                            MagicMock(),
                                                            MagicMock())

        self.p11_mock.Mechanism.assert_called_once()
        self.session.encrypt.assert_called_once_with(key,
                                                     self.plugin._pad(payload),
                                                     mech)
        self.assertEqual(b'\x01\x02\x03\x04\x05', cyphertext)
        self.assertEqual('{"iv": "AQIDBAUGBwgJCgsMDQ4PEA=="}',
                         kek_meta_extended)

    def test_decrypt(self):
        key = 'key1'
        ct = MagicMock()
        self.session.findObjects.return_value = [key]
        self.session.decrypt.return_value = [100, 101, 102, 103] + [12] * 12
        mech = MagicMock()
        self.p11_mock.Mechanism.return_value = mech
        kek_meta_extended = '{"iv": "AQIDBAUGBwgJCgsMDQ4PEA=="}'
        payload = self.plugin.decrypt(ct,
                                      MagicMock(),
                                      kek_meta_extended,
                                      MagicMock())
        self.p11_mock.Mechanism.assert_called_once()
        self.session.decrypt.assert_called_once_with(key,
                                                     ct,
                                                     mech)
        self.assertEqual(b'defg', payload)

    def test_bind_kek_metadata_without_existing_key(self):
        self.session.findObjects.return_value = []  # no existing key
        self.pkcs11.lib.C_GenerateKey.return_value = self.p11_mock.CKR_OK

        self.plugin.bind_kek_metadata(MagicMock())

        self.p11_mock.lib.C_Generate_Key.assert_called_once()
        self.session._template2ckattrlist.assert_called_once()
        self.p11_mock.LowLevel.CK_MECHANISM.assert_called_once()

    def test_bind_kek_metadata_with_existing_key(self):
        self.session.findObjects.return_value = ['key1']  # one key

        self.plugin.bind_kek_metadata(MagicMock())

        gk = self.p11_mock.lib.C_Generate_Key
        # this is a way to test to make sure methods are NOT called
        self.assertItemsEqual([], gk.call_args_list)
        t = self.session._template2ckattrlist
        self.assertItemsEqual([], t.call_args_list)
        m = self.p11_mock.LowLevel.CK_MECHANISM
        self.assertItemsEqual([], m.call_args_list)
