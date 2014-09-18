# Copyright (c) 2014 Rackspace, Inc.
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
from barbican.plugin.interface import secret_store as s
from barbican.plugin.util import translations
from barbican.tests import utils


class WhenNormalizingBeforeEncryption(utils.BaseTestCase):
    def setUp(self):
        super(WhenNormalizingBeforeEncryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.normalize = translations.normalize_before_encryption

    def test_can_normalize_plain_text(self):
        unencrypted, content_type = self.normalize(
            unencrypted='stuff',
            content_type='text/plain',
            content_encoding=''
        )

        self.assertEqual(unencrypted, 'stuff')
        self.assertEqual(content_type, 'text/plain')

    def test_base64_content_gets_decoded(self):
        unencrypted, content_type = self.normalize(
            unencrypted='YmFt',
            content_type='application/octet-stream',
            content_encoding='base64'
        )

        self.assertEqual(unencrypted, 'bam')
        self.assertEqual(content_type, 'application/octet-stream')

    def test_null_content_encoding_gets_passed_through(self):
        unencrypted, content_type = self.normalize(
            unencrypted='bam',
            content_type='application/octet-stream',
            content_encoding=None
        )

        self.assertEqual(unencrypted, 'bam')
        self.assertEqual(content_type, 'application/octet-stream')

    def test_non_encrypted_content_raises_exception(self):
        exception = s.SecretNoPayloadProvidedException
        kwargs = {
            'unencrypted': None,
            'content_type': '',
            'content_encoding': ''
        }

        self.assertRaises(exception, self.normalize, **kwargs)

    def test_invalid_content_type_raises_exception(self):
        exception = s.SecretContentTypeNotSupportedException
        kwargs = {
            'unencrypted': 'stuff',
            'content_type': 'nope',
            'content_encoding': ''
        }

        self.assertRaises(exception, self.normalize, **kwargs)

    def test_invalid_base64_content_raises_exception(self):
        exception = s.SecretPayloadDecodingError
        kwargs = {
            'unencrypted': 'stuff',
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64'
        }

        self.assertRaises(exception, self.normalize, **kwargs)

    def test_content_encoding_must_be_base64(self):
        exception = s.SecretContentEncodingMustBeBase64
        kwargs = {
            'unencrypted': 'stuff',
            'content_type': 'application/octet-stream',
            'content_encoding': 'other_stuff',
            'enforce_text_only': True
        }

        self.assertRaises(exception, self.normalize, **kwargs)

    def test_unsupported_content_encoding_raises_exception(self):
        exception = s.SecretContentEncodingNotSupportedException
        kwargs = {
            'unencrypted': 'stuff',
            'content_type': 'application/octet-stream',
            'content_encoding': 'other_stuff'
        }

        self.assertRaises(exception, self.normalize, **kwargs)


class WhenAnalyzingBeforeDecryption(utils.BaseTestCase):
    def setUp(self):
        super(WhenAnalyzingBeforeDecryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.analyze = translations.analyze_before_decryption

    def test_supported_content_type_doesnt_raise_exception(self):
        try:
            self.analyze('text/plain')
        except Exception as e:
            self.fail('Shouldn\'t have raised: {0}'.format(e))

    def test_unsupported_content_type_raises_exception(self):
        exception = s.SecretAcceptNotSupportedException
        kwargs = {'content_type': 'nope!'}

        self.assertRaises(exception, self.analyze, **kwargs)


class WhenDenormalizingAfterDecryption(utils.BaseTestCase):
    def setUp(self):
        super(WhenDenormalizingAfterDecryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.denormalize = translations.denormalize_after_decryption

    def test_ascii_characters_to_utf8_with_plain_text(self):
        unencrypted = self.denormalize('bam', 'text/plain')
        self.assertEqual(unencrypted, 'bam')

    def test_ascii_characters_to_utf8_with_app_octet_stream(self):
        unencrypted = self.denormalize('bam', 'application/octet-stream')
        self.assertEqual(unencrypted, 'bam')

    def test_non_ascii_character_with_plain_text_raises_exception(self):
        exception = s.SecretAcceptNotSupportedException
        kwargs = {
            'unencrypted': '\xff',
            'content_type': 'text/plain'
        }

        self.assertRaises(exception, self.denormalize, **kwargs)

    def test_content_type_not_text_or_binary_raises_exception(self):
        exception = s.SecretContentTypeNotSupportedException
        kwargs = {
            'unencrypted': 'bam',
            'content_type': 'other_content_type'
        }

        self.assertRaises(exception, self.denormalize, **kwargs)
