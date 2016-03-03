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

from barbican.plugin.crypto import pkcs11
from barbican.tests import utils

if six.PY3:
    long = int


class WhenTestingPKCS11(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingPKCS11, self).setUp()

        self.lib = mock.Mock()
        self.lib.C_Initialize.return_value = pkcs11.CKR_OK
        self.lib.C_OpenSession.side_effect = self._open_session
        self.lib.C_CloseSession.return_value = pkcs11.CKR_OK
        self.lib.C_GetSessionInfo.side_effect = self._get_session_user
        self.lib.C_Login.return_value = pkcs11.CKR_OK
        self.lib.C_FindObjectsInit.return_value = pkcs11.CKR_OK
        self.lib.C_FindObjects.side_effect = self._find_objects_one
        self.lib.C_FindObjectsFinal.return_value = pkcs11.CKR_OK
        self.lib.C_GenerateKey.side_effect = self._generate_key
        self.lib.C_GenerateRandom.side_effect = self._generate_random
        self.lib.C_EncryptInit.return_value = pkcs11.CKR_OK
        self.lib.C_Encrypt.side_effect = self._encrypt
        self.lib.C_DecryptInit.return_value = pkcs11.CKR_OK
        self.lib.C_Decrypt.side_effect = self._decrypt
        self.lib.C_WrapKey.side_effect = self._wrap_key
        self.lib.C_UnwrapKey.side_effect = self._unwrap_key
        self.lib.C_SignInit.return_value = pkcs11.CKR_OK
        self.lib.C_Sign.side_effect = self._sign
        self.lib.C_VerifyInit.return_value = pkcs11.CKR_OK
        self.lib.C_Verify.side_effect = self._verify
        self.lib.C_DestroyObject.return_value = pkcs11.CKR_OK
        self.ffi = pkcs11.build_ffi()
        setattr(self.ffi, 'dlopen', lambda x: self.lib)

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.library_path = '/dev/null'
        self.cfg_mock.login_passphrase = 'foobar'
        self.cfg_mock.rw_session = False
        self.cfg_mock.slot_id = 1
        self.cfg_mock.algorithm = 'CKM_AES_GCM'

        self.pkcs11 = pkcs11.PKCS11(
            self.cfg_mock.library_path, self.cfg_mock.login_passphrase,
            self.cfg_mock.rw_session, self.cfg_mock.slot_id, ffi=self.ffi
        )

    def _generate_random(self, session, buf, length):
        self.ffi.buffer(buf)[:] = b'0' * length
        return pkcs11.CKR_OK

    def _get_session_public(self, session, session_info_ptr):
        if self.cfg_mock.rw_session:
            session_info_ptr[0].state = pkcs11.CKS_RW_PUBLIC_SESSION
        else:
            session_info_ptr[0].state = pkcs11.CKS_RO_PUBLIC_SESSION
        return pkcs11.CKR_OK

    def _get_session_user(self, session, session_info_ptr):
        if self.cfg_mock.rw_session:
            session_info_ptr[0].state = pkcs11.CKS_RW_USER_FUNCTIONS
        else:
            session_info_ptr[0].state = pkcs11.CKS_RO_USER_FUNCTIONS
        return pkcs11.CKR_OK

    def _open_session(self, *args, **kwargs):
        args[4][0] = long(1)
        return pkcs11.CKR_OK

    def _find_objects_one(self, session, obj_handle_ptr, max_count, count):
        obj_handle_ptr[0] = long(2)
        count[0] = 1
        return pkcs11.CKR_OK

    def _find_objects_two(self, session, obj_handle_ptr, max_count, count):
        obj_handle_ptr[0] = long(2)
        count[0] = 2
        return pkcs11.CKR_OK

    def _find_objects_zero(self, session, obj_handle_ptr, max_count, count):
        count[0] = 0
        return pkcs11.CKR_OK

    def _generate_key(self, session, mech, attributes, attributes_len,
                      obj_handle_ptr):
        obj_handle_ptr[0] = long(3)
        return pkcs11.CKR_OK

    def _encrypt(self, session, pt, pt_len, ct, ct_len):
        self.ffi.buffer(ct)[:] = pt[::-1] + b'0' * self.pkcs11.gcmtagsize
        return pkcs11.CKR_OK

    def _decrypt(self, session, ct, ct_len, pt, pt_len):
        tmp = ct[:-self.pkcs11.gcmtagsize][::-1]
        self.ffi.buffer(pt)[:len(tmp)] = tmp
        return pkcs11.CKR_OK

    def _wrap_key(self, *args, **kwargs):
        wrapped_key = args[4]
        wrapped_key_len = args[5]
        wrapped_key_len[0] = long(16)
        if wrapped_key != self.ffi.NULL:
            self.ffi.buffer(wrapped_key)[:] = b'0' * 16
        return pkcs11.CKR_OK

    def _unwrap_key(self, *args, **kwargs):
        unwrapped_key = args[7]
        unwrapped_key[0] = long(1)
        return pkcs11.CKR_OK

    def _sign(self, *args, **kwargs):
        buf = args[3]
        buf_len = args[4]
        self.ffi.buffer(buf)[:] = b'0' * buf_len[0]
        return pkcs11.CKR_OK

    def _verify(self, *args, **kwargs):
        return pkcs11.CKR_OK

    def test_public_get_session(self):
        self.lib.C_GetSessionInfo.side_effect = self._get_session_public
        sess = self.pkcs11.get_session()

        self.assertEqual(sess, 1)

        self.assertEqual(self.lib.C_OpenSession.call_count, 2)
        self.assertEqual(self.lib.C_GetSessionInfo.call_count, 2)
        self.assertEqual(self.lib.C_Login.call_count, 1)
        self.assertEqual(self.lib.C_CloseSession.call_count, 1)

    def test_user_get_session(self):
        self.pkcs11.get_session()

        self.assertEqual(self.lib.C_OpenSession.call_count, 2)
        self.assertEqual(self.lib.C_GetSessionInfo.call_count, 2)
        self.assertEqual(self.lib.C_Login.call_count, 0)

    def test_generate_random(self):
        r = self.pkcs11.generate_random(32, mock.MagicMock())

        self.assertEqual(r, b'0' * 32)

        self.assertEqual(self.lib.C_GenerateRandom.call_count, 2)

    def test_rng_self_test_fail(self):
        def _bad_generate_random(session, buf, length):
            self.ffi.buffer(buf)[:] = b'\x00' * length
            return pkcs11.CKR_OK
        self.lib.C_GenerateRandom.side_effect = _bad_generate_random
        self.assertRaises(pkcs11.P11CryptoPluginException,
                          self.pkcs11._rng_self_test, mock.MagicMock())

    def test_get_key_handle_one_key(self):
        key = self.pkcs11.get_key_handle('foo', mock.MagicMock())

        self.assertEqual(key, 2)

        self.assertEqual(self.lib.C_FindObjectsInit.call_count, 1)
        self.assertEqual(self.lib.C_FindObjects.call_count, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal.call_count, 1)

    def test_get_key_handle_no_keys(self):
        self.lib.C_FindObjects.side_effect = self._find_objects_zero
        key = self.pkcs11.get_key_handle('foo', mock.MagicMock())

        self.assertIsNone(key)

        self.assertEqual(self.lib.C_FindObjectsInit.call_count, 1)
        self.assertEqual(self.lib.C_FindObjects.call_count, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal.call_count, 1)

    def test_get_key_handle_multiple_keys(self):
        self.lib.C_FindObjects.side_effect = self._find_objects_two

        self.assertRaises(pkcs11.P11CryptoPluginKeyException,
                          self.pkcs11.get_key_handle, 'foo', mock.MagicMock())

        self.assertEqual(self.lib.C_FindObjectsInit.call_count, 1)
        self.assertEqual(self.lib.C_FindObjects.call_count, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal.call_count, 1)

    def test_generate_session_key(self):
        key = self.pkcs11.generate_key(16, mock.MagicMock(), encrypt=True)

        self.assertEqual(key, 3)

        self.assertEqual(self.lib.C_GenerateKey.call_count, 1)

    def test_generate_master_key(self):
        key = self.pkcs11.generate_key(16, mock.MagicMock(), key_label='key',
                                       encrypt=True, master_key=True)

        self.assertEqual(key, 3)

        self.assertEqual(self.lib.C_GenerateKey.call_count, 1)

    def test_generate_key_no_flags(self):
        self.assertRaises(pkcs11.P11CryptoPluginException,
                          self.pkcs11.generate_key, mock.MagicMock(),
                          mock.MagicMock())

    def test_generate_master_key_no_label(self):
        self.assertRaises(ValueError, self.pkcs11.generate_key,
                          mock.MagicMock(), mock.MagicMock(),
                          encrypt=True, master_key=True)

    def test_encrypt(self):
        pt = b'0123456789ABCDEF'
        ct = self.pkcs11.encrypt(mock.MagicMock(), pt, mock.MagicMock())

        self.assertEqual(ct['ct'][:len(pt)], pt[::-1])
        self.assertGreater(len(ct['iv']), 0)

        self.assertEqual(self.lib.C_GenerateRandom.call_count, 2)
        self.assertEqual(self.lib.C_EncryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Encrypt.call_count, 1)

    def test_decrypt(self):
        ct = b'FEDCBA9876543210' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.noncesize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize
        self.assertEqual(pt[:pt_len], ct[:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_decrypt_with_pad(self):
        ct = b'\x03\x03\x03CBA9876543210' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.blocksize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize - 3
        self.assertEqual(pt[:pt_len], ct[3:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_decrypt_with_pad_new_iv(self):
        ct = b'\x03\x03\x03CBA9876543210' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.gcmtagsize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize
        self.assertEqual(pt[:pt_len], ct[:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_decrypt_with_pad_wrong_size(self):
        ct = b'\x03\x03\x03CBA987654321' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.blocksize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize
        self.assertEqual(pt[:pt_len], ct[:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_decrypt_with_pad_wrong_length(self):
        ct = b'\x03EDCBA9876543210' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.blocksize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize
        self.assertEqual(pt[:pt_len], ct[:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_decrypt_with_too_large_pad(self):
        ct = b'\x11EDCBA9876543210' + b'0' * self.pkcs11.gcmtagsize
        iv = b'0' * self.pkcs11.blocksize
        pt = self.pkcs11.decrypt(mock.MagicMock(), iv, ct, mock.MagicMock())

        pt_len = len(ct) - self.pkcs11.gcmtagsize
        self.assertEqual(pt[:pt_len], ct[:-self.pkcs11.gcmtagsize][::-1])

        self.assertEqual(self.lib.C_DecryptInit.call_count, 1)
        self.assertEqual(self.lib.C_Decrypt.call_count, 1)

    def test_wrap_key(self):
        wkek = self.pkcs11.wrap_key(mock.Mock(), mock.Mock(), mock.Mock())
        self.assertGreater(len(wkek['iv']), 0)
        self.assertEqual(wkek['wrapped_key'], b'0' * 16)

        self.assertEqual(self.lib.C_GenerateRandom.call_count, 2)
        self.assertEqual(self.lib.C_WrapKey.call_count, 2)

    def test_unwrap_key(self):
        kek = self.pkcs11.unwrap_key(mock.Mock(), b'0' * 16,
                                     b'0' * 16, mock.Mock())
        self.assertEqual(kek, 1)

        self.assertEqual(self.lib.C_UnwrapKey.call_count, 1)

    def test_compute_hmac(self):
        buf = self.pkcs11.compute_hmac(mock.MagicMock(), mock.MagicMock(),
                                       mock.MagicMock())
        self.assertEqual(len(buf), 32)

        self.assertEqual(self.lib.C_SignInit.call_count, 1)
        self.assertEqual(self.lib.C_Sign.call_count, 1)

    def test_verify_hmac(self):
        self.pkcs11.verify_hmac(mock.MagicMock(), mock.MagicMock(),
                                mock.MagicMock(), mock.MagicMock())

        self.assertEqual(self.lib.C_VerifyInit.call_count, 1)
        self.assertEqual(self.lib.C_Verify.call_count, 1)

    def test_destroy_object(self):
        self.pkcs11.destroy_object(mock.MagicMock(), mock.MagicMock())

        self.assertEqual(self.lib.C_DestroyObject.call_count, 1)

    def test_invalid_build_attributes(self):
        self.assertRaises(TypeError, self.pkcs11._build_attributes,
                          [pkcs11.Attribute(pkcs11.CKA_CLASS, {})])
