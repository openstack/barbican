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

import base64

from barbican.plugin.interface import secret_store as s
from barbican.plugin.util import translations
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
        'invalid_base64_content': {
            'exception': s.SecretPayloadDecodingError,
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64'
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
            'expected': base64.b64encode('stuff'.encode('utf-8'))
        },
        'binary_base64': {
            'unencrypted': base64.b64encode('stuff'),
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.b64encode('stuff')
        },
        'binary': {
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.OPAQUE,
            'content_type': 'application/octet-stream',
            'content_encoding': 'binary',
            'expected': base64.b64encode('stuff')
        },
        'symmetric_base64': {
            'unencrypted': base64.b64encode('stuff'),
            'secret_type': s.SecretType.SYMMETRIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': base64.b64encode('stuff')
        },
        'symmetric': {
            'unencrypted': 'stuff',
            'secret_type': s.SecretType.SYMMETRIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'binary',
            'expected': base64.b64encode('stuff')
        },
        'private_base64': {
            'unencrypted': utils.get_private_key(),
            'secret_type': s.SecretType.PRIVATE,
            'content_type': 'application/pkcs8',
            'content_encoding': 'base64',
            'expected': utils.get_private_key()
        },
        'private': {
            'unencrypted': base64.b64decode(
                translations.get_pem_components(utils.get_private_key())[1]),
            'secret_type': s.SecretType.PRIVATE,
            'content_type': 'application/pkcs8',
            'content_encoding': 'binary',
            'expected': utils.get_private_key()
        },
        'public_base64': {
            'unencrypted': utils.get_public_key(),
            'secret_type': s.SecretType.PUBLIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'base64',
            'expected': utils.get_public_key()
        },
        'public': {
            'unencrypted': base64.b64decode(
                translations.get_pem_components(utils.get_public_key())[1]),
            'secret_type': s.SecretType.PUBLIC,
            'content_type': 'application/octet-stream',
            'content_encoding': 'binary',
            'expected': utils.get_public_key()
        },
        'certificate_base64': {
            'unencrypted': utils.get_certificate(),
            'secret_type': s.SecretType.CERTIFICATE,
            'content_type': 'application/pkix-cert',
            'content_encoding': 'base64',
            'expected': utils.get_certificate()
        },
        'certificate': {
            'unencrypted': base64.b64decode(
                translations.get_pem_components(utils.get_certificate())[1]),
            'secret_type': s.SecretType.CERTIFICATE,
            'content_type': 'application/pkix-cert',
            'content_encoding': 'binary',
            'expected': utils.get_certificate()
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

        self.assertEqual(unencrypted, base64.b64encode('stuff'))
        self.assertEqual(content_type, 'text/plain')

    def test_null_content_encoding_gets_passed_through(self):
        unencrypted, content_type = self.normalize(
            unencrypted='bam',
            content_type='application/octet-stream',
            content_encoding=None,
            secret_type=s.SecretType.OPAQUE
        )

        self.assertEqual(base64.b64encode('bam'), unencrypted)
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
class WhenNormalizingPemSecrets(utils.BaseTestCase):

    dataset_for_pem_normalize = {
        'private_key': {
            'pem': utils.get_private_key()
        },
        'public_key': {
            'pem': utils.get_public_key()
        },
        'certificate': {
            'pem': utils.get_certificate()
        }
    }

    dataset_for_bad_pems = {
        'raw_string': {
            'pem': 'fooandstuff'
        },
        'no_header': {
            'pem': utils.get_private_key()[27:]
        },
        'no_footer': {
            'pem': utils.get_private_key()[:-15]
        },
        'no_header_no_footer': {
            'pem': utils.get_private_key()[27:-15]
        }
    }

    dataset_for_to_pem = {
        'private_key': {
            'secret_type': s.SecretType.PRIVATE,
            'pem': utils.get_private_key()
        },
        'public_key': {
            'secret_type': s.SecretType.PUBLIC,
            'pem': utils.get_public_key()
        },
        'certificate': {
            'secret_type': s.SecretType.CERTIFICATE,
            'pem': utils.get_certificate()
        }
    }

    @utils.parameterized_dataset(dataset_for_pem_normalize)
    def test_pem_normalized(self, pem):
        pem_components = translations.get_pem_components(pem)
        self.assertEqual(3, len(pem_components))
        pem_msg = pem_components[0] + pem_components[1] + pem_components[2]
        self.assertEqual(pem, pem_msg)

    @utils.parameterized_dataset(dataset_for_to_pem)
    def test_to_pem(self, secret_type, pem):
        pem_components = translations.get_pem_components(pem)
        content = base64.b64decode(pem_components[1])
        pem_msg = translations.to_pem(secret_type, content, False)
        self.assertEqual(pem, pem_msg)

    @utils.parameterized_dataset(dataset_for_to_pem)
    def test_to_pem_payload_encoded(self, secret_type, pem):
        pem_components = translations.get_pem_components(pem)
        content = pem_components[1]
        pem_msg = translations.to_pem(secret_type, content, True)
        self.assertEqual(pem, pem_msg)

    @utils.parameterized_dataset(dataset_for_bad_pems)
    def test_pem_normalize_raising_exceptions_with(self, pem):
        self.assertRaises(s.SecretPayloadDecodingError,
                          translations.get_pem_components, pem)


@utils.parameterized_test_case
class WhenDenormalizingAfterDecryption(utils.BaseTestCase):

    dataset_for_pem_denormalize = {
        'private_key': {
            'pem': utils.get_private_key(),
            'content_type': 'application/pkcs8'
        },
        'public_key': {
            'pem': utils.get_public_key(),
            'content_type': 'application/octet-stream'
        },
        'certificate': {
            'pem': utils.get_certificate(),
            'content_type': 'application/pkix-cert'
        }
    }

    def setUp(self):
        super(WhenDenormalizingAfterDecryption, self).setUp()

        # Aliasing to reduce the number of line continuations
        self.denormalize = translations.denormalize_after_decryption

    def test_ascii_characters_to_utf8_with_plain_text(self):
        secret = 'bam'
        normalized_secret = secret.encode('utf-8')
        normalized_secret = base64.b64encode(normalized_secret)
        unencrypted = self.denormalize(normalized_secret, 'text/plain')
        self.assertEqual(unencrypted, 'bam')

    def test_ascii_characters_to_utf8_with_app_octet_stream(self):
        unencrypted = self.denormalize(base64.b64encode('bam'),
                                       'application/octet-stream')
        self.assertEqual(unencrypted, 'bam')

    def test_non_ascii_character_with_plain_text_raises_exception(self):
        exception = s.SecretAcceptNotSupportedException
        kwargs = {
            'unencrypted': base64.b64encode('\xff'),
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
    def test_denormalize_pem(self, pem, content_type):
        pem_components = translations.get_pem_components(pem)
        secret = base64.b64decode(pem_components[1])
        denorm_secret = self.denormalize(pem, content_type)
        self.assertEqual(secret, denorm_secret)
