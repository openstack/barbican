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

import base64
import unittest

from barbican.crypto import extension_manager as em
from barbican.crypto import mime_types as mt


class WhenTestingNormalizeBeforeEncryptionForBinary(unittest.TestCase):

    def setUp(self):
        self.unencrypted = 'AAAAAAAA'
        self.content_type = 'application/octet-stream'
        self.content_encoding = 'base64'
        self.enforce_text_only = False

    def test_encrypt_binary_from_base64(self):
        unenc, content = em.normalize_before_encryption(self.unencrypted,
                                                        self.content_type,
                                                        self.content_encoding,
                                                        self.enforce_text_only)
        self.assertEqual(self.content_type, content)
        self.assertEqual(base64.b64decode(self.unencrypted), unenc)

    def test_encrypt_binary_directly(self):
        self.content_encoding = None
        unenc, content = em.normalize_before_encryption(self.unencrypted,
                                                        self.content_type,
                                                        self.content_encoding,
                                                        self.enforce_text_only)
        self.assertEqual(self.content_type, content)
        self.assertEqual(self.unencrypted, unenc)

    def test_encrypt_fail_binary_unknown_encoding(self):
        self.content_encoding = 'gzip'

        with self.assertRaises(em.CryptoContentEncodingNotSupportedException)\
                as cm:
            unenc, content = em. \
                normalize_before_encryption(self.unencrypted,
                                            self.content_type,
                                            self.content_encoding,
                                            self.enforce_text_only)
        ex = cm.exception
        self.assertEqual(self.content_encoding, ex.content_encoding)

    def test_encrypt_fail_binary_force_text_based_no_encoding(self):
        self.content_encoding = None
        self.enforce_text_only = True
        with self.assertRaises(em.CryptoContentEncodingMustBeBase64):
            unenc, content = em. \
                normalize_before_encryption(self.unencrypted,
                                            self.content_type,
                                            self.content_encoding,
                                            self.enforce_text_only)

    def test_encrypt_fail_unknown_content_type(self):
        self.content_type = 'bogus'
        with self.assertRaises(em.CryptoContentTypeNotSupportedException)\
                as cm:
            unenc, content = em \
                .normalize_before_encryption(self.unencrypted,
                                             self.content_type,
                                             self.content_encoding,
                                             self.enforce_text_only)
        ex = cm.exception
        self.assertEqual(self.content_type, ex.content_type)


class WhenTestingNormalizeBeforeEncryptionForText(unittest.TestCase):

    def setUp(self):
        self.unencrypted = 'AAAAAAAA'
        self.content_type = 'text/plain'
        self.content_encoding = 'base64'
        self.enforce_text_only = False

    def test_encrypt_text_ignore_encoding(self):
        unenc, content = em.normalize_before_encryption(self.unencrypted,
                                                        self.content_type,
                                                        self.content_encoding,
                                                        self.enforce_text_only)
        self.assertEqual(self.content_type, content)
        self.assertEqual(self.unencrypted, unenc)

    def test_encrypt_text_not_normalized_ignore_encoding(self):
        self.content_type = 'text/plain;charset=utf-8'
        unenc, content = em.normalize_before_encryption(self.unencrypted,
                                                        self.content_type,
                                                        self.content_encoding,
                                                        self.enforce_text_only)
        self.assertEqual(mt.normalize_content_type(self.content_type),
                         content)
        self.assertEqual(self.unencrypted.encode('utf-8'), unenc)


class WhenTestingAnalyzeBeforeDecryption(unittest.TestCase):

    def setUp(self):
        self.content_type = 'application/octet-stream'
        self.content_encoding = 'base64'

    def test_decrypt_binary_from_base64(self):
        b64needed = em.analyze_before_decryption(self.content_type,
                                                 self.content_encoding)
        self.assertTrue(b64needed)

    def test_decrypt_binary_not_base64(self):
        self.content_encoding = None
        b64needed = em.analyze_before_decryption(self.content_type,
                                                 self.content_encoding)
        self.assertFalse(b64needed)

    def test_decrypt_text(self):
        self.content_type = 'text/plain'
        b64needed = em.analyze_before_decryption(self.content_type,
                                                 self.content_encoding)
        self.assertFalse(b64needed)

    def test_decrypt_fail_bogus_content_type(self):
        self.content_type = 'bogus'
        with self.assertRaises(em.CryptoAcceptNotSupportedException) as cm:
            em.analyze_before_decryption(self.content_type,
                                         self.content_encoding)
        ex = cm.exception
        self.assertEqual(self.content_type, ex.accept)

    def test_decrypt_fail_unknown_encoding_for_binary_content_type(self):
        self.content_encoding = 'gzip'
        with self.assertRaises(em.CryptoAcceptEncodingNotSupportedException) \
                as cm:
            em.analyze_before_decryption(self.content_type,
                                         self.content_encoding)
        ex = cm.exception
        self.assertEqual(self.content_encoding, ex.accept_encoding)


class WhenTestingDenormalizeAfterDecryption(unittest.TestCase):

    def setUp(self):
        self.unencrypted = 'AAAAAAAA'
        self.content_type = 'application/octet-stream'
        self.is_base64_needed = True

    def test_decrypt_binary_from_base64(self):
        unenc = em.denormalize_after_decryption(self.unencrypted,
                                                self.content_type,
                                                self.is_base64_needed)
        self.assertEqual(base64.b64encode(self.unencrypted), unenc)

    def test_decrypt_fail_binary_not_base64(self):
        unenc = em.denormalize_after_decryption(self.unencrypted,
                                                self.content_type,
                                                False)
        self.assertEqual(self.unencrypted, unenc)

    def test_decrypt_text(self):
        self.content_type = 'text/plain'
        unenc = em.denormalize_after_decryption(self.unencrypted,
                                                self.content_type,
                                                self.is_base64_needed)
        self.assertEqual(self.unencrypted.decode('utf-8'), unenc)

    def test_decrypt_fail_unknown_content_type(self):
        self.content_type = 'bogus'
        with self.assertRaises(em.CryptoGeneralException):
            em.denormalize_after_decryption(self.unencrypted,
                                            self.content_type,
                                            False)

    def test_decrypt_fail_bad_decode(self):
        self.unencrypted = None
        with self.assertRaises(em.CryptoGeneralException):
            em.denormalize_after_decryption(self.unencrypted,
                                            self.content_type,
                                            self.is_base64_needed)
