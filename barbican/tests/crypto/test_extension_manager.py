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
import testtools

from barbican.crypto import extension_manager as em
from barbican.crypto import mime_types as mt
from barbican.crypto.plugin import CryptoPluginBase, PluginSupportTypes


class TestSupportsCryptoPlugin(CryptoPluginBase):
    """Crypto plugin for testing supports."""

    def encrypt(self, unencrypted, kek_meta_dto, tenant):
        raise NotImplementedError()

    def decrypt(self, encrypted, kek_meta_dto, kek_meta_extended, tenant):
        raise NotImplementedError()

    def bind_kek_metadata(self, kek_meta_dto):
        return None

    def create(self, bit_length, type_enum, algorithm=None, mode=None):
        raise NotImplementedError()

    def supports(self, type_enum, algorithm=None, mode=None):
        return False


class WhenTestingNormalizeBeforeEncryptionForBinary(testtools.TestCase):

    def setUp(self):
        super(WhenTestingNormalizeBeforeEncryptionForBinary, self).setUp()
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

        ex = self.assertRaises(
            em.CryptoContentEncodingNotSupportedException,
            em.normalize_before_encryption,
            self.unencrypted,
            self.content_type,
            self.content_encoding,
            self.enforce_text_only,
        )
        self.assertEqual(self.content_encoding, ex.content_encoding)

    def test_encrypt_fail_binary_force_text_based_no_encoding(self):
        self.content_encoding = None
        self.enforce_text_only = True
        self.assertRaises(
            em.CryptoContentEncodingMustBeBase64,
            em.normalize_before_encryption,
            self.unencrypted,
            self.content_type,
            self.content_encoding,
            self.enforce_text_only,
        )

    def test_encrypt_fail_unknown_content_type(self):
        self.content_type = 'bogus'
        ex = self.assertRaises(
            em.CryptoContentTypeNotSupportedException,
            em.normalize_before_encryption,
            self.unencrypted,
            self.content_type,
            self.content_encoding,
            self.enforce_text_only,
        )
        self.assertEqual(self.content_type, ex.content_type)


class WhenTestingNormalizeBeforeEncryptionForText(testtools.TestCase):

    def setUp(self):
        super(WhenTestingNormalizeBeforeEncryptionForText, self).setUp()

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

    def test_raises_on_bogus_content_type(self):
        content_type = 'text/plain; charset=ISO-8859-1'

        self.assertRaises(
            em.CryptoContentTypeNotSupportedException,
            em.normalize_before_encryption,
            self.unencrypted,
            content_type,
            self.content_encoding,
            self.enforce_text_only
        )

    def test_raises_on_no_payload(self):
        content_type = 'text/plain; charset=ISO-8859-1'
        self.assertRaises(
            em.CryptoNoPayloadProvidedException,
            em.normalize_before_encryption,
            None,
            content_type,
            self.content_encoding,
            self.enforce_text_only
        )


class WhenTestingAnalyzeBeforeDecryption(testtools.TestCase):

    def setUp(self):
        super(WhenTestingAnalyzeBeforeDecryption, self).setUp()

        self.content_type = 'application/octet-stream'

    def test_decrypt_fail_bogus_content_type(self):
        self.content_type = 'bogus'

        ex = self.assertRaises(
            em.CryptoAcceptNotSupportedException,
            em.analyze_before_decryption,
            self.content_type,
        )
        self.assertEqual(self.content_type, ex.accept)


class WhenTestingDenormalizeAfterDecryption(testtools.TestCase):

    def setUp(self):
        super(WhenTestingDenormalizeAfterDecryption, self).setUp()

        self.unencrypted = 'AAAAAAAA'
        self.content_type = 'application/octet-stream'

    def test_decrypt_fail_binary(self):
        unenc = em.denormalize_after_decryption(self.unencrypted,
                                                self.content_type)
        self.assertEqual(self.unencrypted, unenc)

    def test_decrypt_text(self):
        self.content_type = 'text/plain'
        unenc = em.denormalize_after_decryption(self.unencrypted,
                                                self.content_type)
        self.assertEqual(self.unencrypted.decode('utf-8'), unenc)

    def test_decrypt_fail_unknown_content_type(self):
        self.content_type = 'bogus'
        self.assertRaises(
            em.CryptoGeneralException,
            em.denormalize_after_decryption,
            self.unencrypted,
            self.content_type,
        )

    def test_decrypt_fail_binary_as_plain(self):
        self.unencrypted = '\xff'
        self.content_type = 'text/plain'
        self.assertRaises(
            em.CryptoAcceptNotSupportedException,
            em.denormalize_after_decryption,
            self.unencrypted,
            self.content_type,
        )


class WhenTestingCryptoExtensionManager(testtools.TestCase):

    def setUp(self):
        super(WhenTestingCryptoExtensionManager, self).setUp()
        self.manager = em.CryptoExtensionManager()

    def test_create_supported_algorithm(self):
        skg = PluginSupportTypes.SYMMETRIC_KEY_GENERATION
        self.assertEqual(skg, self.manager._determine_type('AES'))
        self.assertEqual(skg, self.manager._determine_type('aes'))
        self.assertEqual(skg, self.manager._determine_type('DES'))
        self.assertEqual(skg, self.manager._determine_type('des'))

    def test_create_unsupported_algorithm(self):
        self.assertRaises(
            em.CryptoAlgorithmNotSupportedException,
            self.manager._determine_type,
            'faux_alg',
        )

    def test_encrypt_no_plugin_found(self):
        self.manager.extensions = []
        self.assertRaises(
            em.CryptoPluginNotFound,
            self.manager.encrypt,
            'payload',
            'content_type',
            'content_encoding',
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_encrypt_no_supported_plugin(self):
        plugin = TestSupportsCryptoPlugin()
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        self.assertRaises(
            em.CryptoSupportedPluginNotFound,
            self.manager.encrypt,
            'payload',
            'content_type',
            'content_encoding',
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_decrypt_no_plugin_found(self):
        """ Passing mocks here causes CryptoPluginNotFound because the mock
        won't match any of the available plugins
        """
        self.assertRaises(
            em.CryptoPluginNotFound,
            self.manager.decrypt,
            'text/plain',
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_decrypt_no_supported_plugin_found(self):
        """ Similar to test_decrypt_no_plugin_found, but in this case
        no plugin can be found that supports the specified secret's
        encrypted data.
        """
        fake_secret = mock.MagicMock()
        fake_datum = mock.MagicMock()
        fake_datum.kek_meta_tenant = mock.MagicMock()
        fake_secret.encrypted_data = [fake_datum]
        self.assertRaises(
            em.CryptoPluginNotFound,
            self.manager.decrypt,
            'text/plain',
            fake_secret,
            mock.MagicMock(),
        )

    def test_generate_data_encryption_key_no_plugin_found(self):
        self.manager.extensions = []
        self.assertRaises(
            em.CryptoPluginNotFound,
            self.manager.generate_data_encryption_key,
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_generate_data_encryption_key_no_supported_plugin(self):
        plugin = TestSupportsCryptoPlugin()
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        self.assertRaises(
            em.CryptoSupportedPluginNotFound,
            self.manager.generate_data_encryption_key,
            mock.MagicMock(algorithm='AES'),
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
        )

    def test_find_or_create_kek_objects_bind_returns_none(self):
        plugin = TestSupportsCryptoPlugin()
        kek_repo = mock.MagicMock(name='kek_repo')
        bind_completed = mock.MagicMock(bind_completed=False)
        kek_repo.find_or_create_kek_datum.return_value = bind_completed
        self.assertRaises(
            em.CryptoKEKBindingException,
            self.manager._find_or_create_kek_objects,
            plugin,
            mock.MagicMock(),
            kek_repo,
        )

    def test_find_or_create_kek_objects_saves_to_repo(self):
        kek_repo = mock.MagicMock(name='kek_repo')
        bind_completed = mock.MagicMock(bind_completed=False)
        kek_repo.find_or_create_kek_datum.return_value = bind_completed
        self.manager._find_or_create_kek_objects(
            mock.MagicMock(),
            mock.MagicMock(),
            kek_repo
        )
        kek_repo.save.assert_called_once()
