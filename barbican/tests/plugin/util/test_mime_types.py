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

from barbican.model import models
from barbican.plugin.util import mime_types
from barbican.tests import utils


class WhenTestingIsBase64ProcessingNeeded(utils.BaseTestCase):

    def test_is_base64_needed(self):
        r = mime_types.is_base64_processing_needed('application/octet-stream',
                                                   'base64')
        self.assertTrue(r)

    def test_is_base64_plus_needed(self):
        r = mime_types.is_base64_processing_needed('application/octet-stream',
                                                   'base64;q=0.5, '
                                                   'gzip;q=0.6, compress')
        self.assertTrue(r)

    def test_not_base64_needed_binary(self):
        r = mime_types.is_base64_processing_needed('application/octet-stream',
                                                   None)
        self.assertFalse(r)

    def test_not_base64_needed_invalid_content_type(self):
        r = mime_types.is_base64_processing_needed('bababooey',
                                                   'base64')
        self.assertFalse(r)

    def test_not_base64_needed_text(self):
        r = mime_types.is_base64_processing_needed('text/plain',
                                                   'base64')
        self.assertFalse(r)


class WhenTestingIsBase64ProcessingSupported(utils.BaseTestCase):

    def test_is_base64_supported_application_octet_stream(self):
        r = mime_types.is_base64_encoding_supported('application/octet-stream')
        self.assertTrue(r)

    def test_is_base64_supported_with_unsupported_values(self):
        mimes_where_base64_is_not_supported = ['text/plain',
                                               'bogus']
        for mime in mimes_where_base64_is_not_supported:
            r = mime_types.is_base64_encoding_supported(mime)
            self.assertFalse(r)


class WhenTestingAllowBinaryContent(utils.BaseTestCase):

    def test_binary_content_without_encoding(self):
        r = mime_types.use_binary_content_as_is('application/octet-stream',
                                                None)
        self.assertTrue(r)

    def test_binary_content_with_valid_encoding(self):
        r = mime_types.use_binary_content_as_is('application/octet-stream',
                                                'binary')
        self.assertTrue(r)

    def test_binary_content_with_encoding(self):
        r = mime_types.use_binary_content_as_is('application/octet-stream',
                                                'binary;q=0.5, '
                                                'gzip;q=0.6, compress')
        self.assertTrue(r)

    def test_binary_content_with_base64_encoding(self):
        r = mime_types.use_binary_content_as_is('application/octet-stream',
                                                'base64')
        self.assertFalse(r)

    def test_not_allow_with_invalid_content_type(self):
        r = mime_types.use_binary_content_as_is('invalid_conent_type',
                                                'binary')
        self.assertFalse(r)

    def test_plain_content_with_base64_encoding(self):
        r = mime_types.use_binary_content_as_is('text/plain',
                                                'base64')
        self.assertFalse(r)


class WhenTestingAugmentFieldsWithContentTypes(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingAugmentFieldsWithContentTypes, self).setUp()

        self.secret = models.Secret({})
        self.secret.secret_id = "secret#1"
        self.datum = models.EncryptedDatum(self.secret)
        self.secret.encrypted_data = [self.datum]

    def test_static_supported_plain_text(self):
        for pt in mime_types.PLAIN_TEXT:
            self.assertEqual('text/plain', mime_types.INTERNAL_CTYPES[pt])

    def test_static_supported_binary(self):
        for bin in mime_types.BINARY:
            self.assertIn(mime_types.INTERNAL_CTYPES[bin],
                          mime_types.BINARY)

    def test_static_content_to_encodings(self):
        self.assertIn('text/plain', mime_types.CTYPES_TO_ENCODINGS)
        self.assertIsNone(mime_types.CTYPES_TO_ENCODINGS['text/plain'])

        self.assertIn('application/aes', mime_types.CTYPES_TO_ENCODINGS)
        self.assertIsNone(mime_types.CTYPES_TO_ENCODINGS['application/aes'])

        self.assertIn('application/octet-stream',
                      mime_types.CTYPES_TO_ENCODINGS)
        self.assertIn('base64', mime_types.CTYPES_TO_ENCODINGS[
            'application/octet-stream'])
        self.assertIn('binary', mime_types.CTYPES_TO_ENCODINGS[
            'application/octet-stream'])

    def test_secret_with_matching_datum(self):
        for ct in mime_types.SUPPORTED:
            self._test_secret_and_datum_for_content_type(ct)

    def test_secret_with_non_matching_datum(self):
        self.datum.content_type = "bababooey"
        fields = mime_types.augment_fields_with_content_types(self.secret)
        self.assertNotIn("bababooey", fields)

    def _test_secret_and_datum_for_content_type(self, content_type):
        self.assertIn(content_type, mime_types.INTERNAL_CTYPES)

        # TODO(rm_work): This is deprecated and should eventually be removed
        self.datum.content_type = mime_types.INTERNAL_CTYPES[content_type]

        # Set up the Secret Metadata
        content_meta = models.SecretStoreMetadatum('content_type',
                                                   self.datum.content_type)
        self.secret.secret_store_metadata['content_type'] = content_meta

        fields = mime_types.augment_fields_with_content_types(self.secret)

        self.assertIn('content_types', fields)
        content_types = fields['content_types']
        self.assertIn('default', content_types)
        self.assertEqual(self.datum.content_type, content_types['default'])


class WhenTestingNormalizationOfMIMETypes(utils.BaseTestCase):

    def test_plain_text_normalization(self):
        mimes = ['text/plain',
                 '   text/plain  ',
                 'text/plain;charset=utf-8',
                 'text/plain;charset=UTF-8',
                 'text/plain; charset=utf-8',
                 'text/plain; charset=UTF-8',
                 'text/plain;  charset=utf-8',
                 'text/plain;  charset=UTF-8',
                 'text/plain ; charset = utf-8',
                 'text/plain ; charset = UTF-8']
        for mime in mimes:
            self._test_plain_text_mime_type(mime)

    def _test_plain_text_mime_type(self, mime):
        r = mime_types.normalize_content_type(mime)
        self.assertEqual('text/plain', r)

    def test_unsupported_charset_in_plain_text_mime(self):
        mime = 'text/plain; charset=ISO-8859-1'
        r = mime_types.normalize_content_type(mime)
        self.assertEqual(mime, r)

    def test_malformed_charset_in_plain_text_mime(self):
        mime = 'text/plain; charset is ISO-8859-1'
        r = mime_types.normalize_content_type(mime)
        self.assertEqual(mime, r)

    def test_binary_normalization(self):
        mime = 'application/octet-stream'
        r = mime_types.normalize_content_type(mime)
        self.assertEqual('application/octet-stream', r)

    def test_bogus_mime_normalization(self):
        mime = 'something/bogus'
        r = mime_types.normalize_content_type(mime)
        self.assertEqual('something/bogus', r)


@utils.parameterized_test_case
class WhenTestingIfContentTypeAndEncodingSupported(utils.BaseTestCase):

    @utils.parameterized_dataset({
        'plaintext_none': ['text/plain', None],
        'octectstream_base64': ['application/octet-stream', 'base64'],
        'pkcs8_base64': ['application/pkcs8', 'base64'],
        'pkix_base64': ['application/pkix-cert', 'base64'],
    })
    def test_content_type_encoding_supported(self, content_type, encoding):
        self.assertTrue(mime_types.is_content_type_with_encoding_supported(
            content_type,
            encoding))

    @utils.parameterized_dataset({
        'plaintext_none': ['text/plain', 'base64'],
        'octectstream_no_encoding': ['application/octet-stream', None],
        'pkcs8_no_encoding': ['application/pkcs8', None],
        'pkix_no_encoding': ['application/pkix-cert', None],
        'unknown_with_valid_encoding': ['application/uknown-content-type',
                                        'base64']
    })
    def test_content_type_encoding_not_supported(self, content_type, encoding):
        self.assertFalse(mime_types.is_content_type_with_encoding_supported(
            content_type,
            encoding))
