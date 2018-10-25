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

from oslo_serialization import base64

from barbican.plugin.interface import secret_store as s
from barbican.plugin.util import translations
from barbican.tests import keys
from barbican.tests import utils


@utils.parameterized_test_case
class WhenNormalizingBeforeEncryption(utils.BaseTestCase):
    dataset_for_raised_exceptions = {
        'non_encrypted_content': {
            'exception': s.SecretNoPayloadProvidedException,
            'unencrypted': None,
            'secret_type': s.SecretType.OPAQUE,
            'content_type': '',
            'content_encoding': ''
        },
        'invalid_content_type': {
            'exception': s.SecretContentTypeNotSupportedException,
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'nope',
            'content_encoding': ''
        },
        'content_encoding_isnt_base64': {
            'exception': s.SecretContentEncodingMustBeBase64,
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'other_stuff',
            'enforce_text_only': True
        },
        'unsupported_content_encoding': {
            'exception': s.SecretContentEncodingNotSupportedException,
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'other_stuff'
        }
    }

    dataset_for_normalization = {
        'plain_text': {
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'text/plain',
            'content_encoding': '',
            'expected': base64.encode_as_bytes('stuff')
        },
        'binary_base64': {
            'unencrypted': base64.encode_as_bytes('stuff'),
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.encode_as_bytes('stuff')
        },
        'binary': {
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': None,
            'expected': base64.encode_as_bytes('stuff')
        },
        'symmetric_base64': {
            'unencrypted': base64.encode_as_bytes('stuff'),
            'secret_type': s.SecretType.SYMMETRIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.encode_as_bytes('stuff')
        },
        'symmetric': {
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.SYMMETRIC,
            'content_type': 'application/octet-stream',
            'content_encoding': None,
            'expected': base64.encode_as_bytes('stuff')
        },
        'private_base64': {
            'unencrypted': base64.encode_as_bytes(keys.get_private_key_pem()),
            'secret_type': s.SecretType.PRIVATE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.encode_as_bytes(keys.get_private_key_pem())
        },
        'private': {
            'unencrypted': keys.get_private_key_pem(),
            'secret_type': s.SecretType.PRIVATE,
            'content_type': 'application/octet-stream',
            'content_encoding': None,
            'expected': base64.encode_as_bytes(keys.get_private_key_pem())
        },
        'public_base64': {
            'unencrypted': base64.encode_as_bytes(keys.get_public_key_pem()),
            'secret_type': s.SecretType.PUBLIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.encode_as_bytes(keys.get_public_key_pem())
        },
        'public': {
            'unencrypted': keys.get_public_key_pem(),
            'secret_type': s.SecretType.PUBLIC,
            'content_type': 'application/octet-stream',
            'content_encoding': None,
            'expected': base64.encode_as_bytes(keys.get_public_key_pem())
        },
        'certificate_base64': {
            'unencrypted': base64.encode_as_bytes(keys.get_certificate_pem()),
            'secret_type': s.SecretType.CERTIFICATE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.encode_as_bytes(keys.get_certificate_pem())
        },
        'certificate': {
            'unencrypted': keys.get_certificate_pem(),
            'secret_type': s.SecretType.CERTIFICATE,
            'content_type': 'application/octet-stream',
            'content_encoding': None,
            'expected': base64.encode_as_bytes(keys.get_certificate_pem())
        },
    }

    def setUp(self):
        super(WhenNormalizingBeforeEncryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.normalize = translations.normalize_before_encryption

    @utils.parameterized_dataset(dataset_for_normalization)
    def test_can_normalize(self, **kwargs):
        unencrypted, content_type = self.normalize(
            unencrypted=kwargs['unencrypted'],
            content_type=kwargs['content_type'],
            content_encoding=kwargs['content_encoding'],
            secret_type=kwargs['secret_type']
        )
        self.assertEqual(kwargs['expected'], unencrypted)
        self.assertEqual(kwargs['content_type'], content_type)

    def test_can_normalize_tmp_plain_text(self):
        unencrypted, content_type = self.normalize(
            unencrypted='stuff',
            content_type='text/plain',
            content_encoding='',
            secret_type=s.SecretType.OPAQUE
        )

        self.assertEqual(base64.encode_as_bytes('stuff'), unencrypted)
        self.assertEqual('text/plain', content_type)

    def test_null_content_encoding_gets_passed_through(self):
        unencrypted, content_type = self.normalize(
            unencrypted='bam',
            content_type='application/octet-stream',
            content_encoding=None,
            secret_type=s.SecretType.OPAQUE
        )

        self.assertEqual(base64.encode_as_bytes('bam'), unencrypted)
        self.assertEqual('application/octet-stream', content_type)

    def test_can_normalize_base64_str(self):
        unencrypted, content_type = self.normalize(
            unencrypted=base64.encode_as_bytes('stuff').decode('utf-8'),
            content_type='application/octet-stream',
            content_encoding='base64',
            secret_type=s.SecretType.OPAQUE
        )

        self.assertEqual(base64.encode_as_bytes('stuff'), unencrypted)
        self.assertEqual('application/octet-stream', content_type)

    def test_can_normalize_base64_bytes(self):
        unencrypted, content_type = self.normalize(
            unencrypted=base64.encode_as_bytes('stuff'),
            content_type='application/octet-stream',
            content_encoding='base64',
            secret_type=s.SecretType.OPAQUE
        )

        self.assertEqual(base64.encode_as_bytes('stuff'), unencrypted)
        self.assertEqual('application/octet-stream', content_type)

    @utils.parameterized_dataset(dataset_for_raised_exceptions)
    def test_normalize_raising_exceptions_with(self, exception, **kwargs):
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


@utils.parameterized_test_case
class WhenDenormalizingAfterDecryption(utils.BaseTestCase):

    dataset_for_pem_denormalize = {
        'private_key': {
            'encoded_pem': base64.encode_as_bytes(keys.get_private_key_pem()),
            'content_type': 'application/octet-stream'
        },
        'public_key': {
            'encoded_pem': base64.encode_as_bytes(keys.get_public_key_pem()),
            'content_type': 'application/octet-stream'
        },
        'certificate': {
            'encoded_pem': base64.encode_as_bytes(keys.get_certificate_pem()),
            'content_type': 'application/octet-stream'
        }
    }

    def setUp(self):
        super(WhenDenormalizingAfterDecryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.denormalize = translations.denormalize_after_decryption

    def test_ascii_characters_to_utf8_with_plain_text(self):
        secret = 'bam'
        normalized_secret = base64.encode_as_bytes(secret)
        unencrypted = self.denormalize(normalized_secret, 'text/plain')
        self.assertEqual('bam', unencrypted)

    def test_ascii_characters_to_utf8_with_app_octet_stream(self):
        unencrypted = self.denormalize(base64.encode_as_bytes('bam'),
                                       'application/octet-stream')
        self.assertEqual(b'bam', unencrypted)

    def test_non_ascii_character_with_plain_text_raises_exception(self):
        exception = s.SecretAcceptNotSupportedException
        kwargs = {
            'unencrypted': base64.encode_as_bytes(b'\xff'),
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

    @utils.parameterized_dataset(dataset_for_pem_denormalize)
    def test_denormalize_pem(self, encoded_pem, content_type):
        denorm_secret = self.denormalize(encoded_pem, content_type)
        self.assertEqual(base64.decode_as_bytes(encoded_pem), denorm_secret)


class WhenConvertingKeyFormats(utils.BaseTestCase):
    def test_passes_convert_private_pem_to_der(self):
        pem = keys.get_private_key_pem()
        expected_der = keys.get_private_key_der()
        der = translations.convert_pem_to_der(
            pem, s.SecretType.PRIVATE)
        self.assertEqual(expected_der, der)

    def test_passes_convert_private_der_to_pem(self):
        der = keys.get_private_key_der()
        expected_pem = keys.get_private_key_pem()
        pem = translations.convert_der_to_pem(
            der, s.SecretType.PRIVATE)
        self.assertEqual(expected_pem, pem)

    def test_passes_convert_public_pem_to_der(self):
        pem = keys.get_public_key_pem()
        expected_der = keys.get_public_key_der()
        der = translations.convert_pem_to_der(
            pem, s.SecretType.PUBLIC)
        self.assertEqual(expected_der, der)

    def test_passes_convert_public_der_to_pem(self):
        der = keys.get_public_key_der()
        expected_pem = keys.get_public_key_pem()
        pem = translations.convert_der_to_pem(
            der, s.SecretType.PUBLIC)
        self.assertEqual(expected_pem, pem)

    def test_passes_convert_certificate_pem_to_der(self):
        pem = keys.get_certificate_pem()
        expected_der = keys.get_certificate_der()
        der = translations.convert_pem_to_der(
            pem, s.SecretType.CERTIFICATE)
        self.assertEqual(expected_der, der)

    def test_passes_convert_certificate_der_to_pem(self):
        der = keys.get_certificate_der()
        expected_pem = keys.get_certificate_pem()
        pem = translations.convert_der_to_pem(
            der, s.SecretType.CERTIFICATE)
        self.assertEqual(expected_pem, pem)

    def test_passes_certificate_conversion(self):
        pem = keys.get_certificate_pem()
        der = translations.convert_pem_to_der(
            pem, s.SecretType.CERTIFICATE)
        converted_pem = translations.convert_der_to_pem(
            der, s.SecretType.CERTIFICATE)
        self.assertEqual(pem, converted_pem)

    def test_should_raise_to_pem_with_bad_secret_type(self):
        self.assertRaises(s.SecretGeneralException,
                          translations.convert_der_to_pem,
                          "der", "bad type")

    def test_should_raise_to_der_with_bad_secret_type(self):
        self.assertRaises(s.SecretGeneralException,
                          translations.convert_pem_to_der,
                          "pem", "bad type")
