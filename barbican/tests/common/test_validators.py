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

import datetime
import unittest

from oslo_serialization import base64
from oslo_utils import timeutils

from barbican.common import exception as excep
from barbican.common import validators
from barbican.tests import keys
from barbican.tests import utils

VALID_EXTENSIONS = "valid extensions"
VALID_FULL_CMC = "valid CMC"


def get_symmetric_key_req():
    return {'name': 'mysymmetrickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'aes',
            'bit_length': 256,
            'secret_type': 'symmetric',
            'payload': 'gF6+lLoF3ohA9aPRpt+6bQ=='}


def get_private_key_req():
    return {'name': 'myprivatekey',
            'payload_content_type': 'application/pkcs8',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'private',
            'payload': base64.encode_as_text(keys.get_private_key_pem())}


def get_public_key_req():
    return {'name': 'mypublickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'public',
            'payload': base64.encode_as_text(keys.get_public_key_pem())}


def get_certificate_req():
    return {'name': 'mycertificate',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'certificate',
            'payload': base64.encode_as_text(keys.get_certificate_pem())}


def get_passphrase_req():
    return {'name': 'mypassphrase',
            'payload_content_type': 'text/plain',
            'secret_type': 'passphrase',
            'payload': 'mysecretpassphrase'}


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingSecretValidator())

    return suite


class WhenTestingValidatorsFunctions(utils.BaseTestCase):

    def test_secret_too_big_is_false_for_small_secrets(self):
        data = b'\xb0'

        is_too_big = validators.secret_too_big(data)

        self.assertFalse(is_too_big)

    def test_secret_too_big_is_true_for_big_secrets(self):
        data = b'\x01' * validators.CONF.max_allowed_secret_in_bytes
        data += b'\x01'

        is_too_big = validators.secret_too_big(data)

        self.assertTrue(is_too_big)

    def test_secret_too_big_is_true_for_big_unicode_secrets(self):
        beer = '\U0001F37A'
        data = beer * (validators.CONF.max_allowed_secret_in_bytes // 4)
        data += '1'

        is_too_big = validators.secret_too_big(data)

        self.assertTrue(is_too_big)


@utils.parameterized_test_case
class WhenTestingSecretValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretValidator, self).setUp()

        self.name = 'name'
        self.payload = 'not-encrypted'
        self.payload_content_type = 'text/plain'
        self.secret_algorithm = 'algo'
        self.secret_bit_length = 512
        self.secret_type = 'opaque'
        self.secret_mode = 'cytype'

        self.secret_req = {'name': self.name,
                           'payload_content_type': self.payload_content_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'secret_type': self.secret_type,
                           'mode': self.secret_mode,
                           'payload': self.payload}

        self.validator = validators.NewSecretValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.secret_req)

    def test_should_validate_no_name(self):
        del self.secret_req['name']
        self.validator.validate(self.secret_req)

    def test_should_validate_empty_name(self):
        self.secret_req['name'] = '    '
        self.validator.validate(self.secret_req)

    def test_should_validate_null_name(self):
        self.secret_req['name'] = None
        self.validator.validate(self.secret_req)

    def test_should_validate_no_payload(self):
        del self.secret_req['payload']
        del self.secret_req['payload_content_type']
        result = self.validator.validate(self.secret_req)

        self.assertNotIn('payload', result)

    def test_should_validate_payload_with_whitespace(self):
        self.secret_req['payload'] = '  ' + self.payload + '    '
        result = self.validator.validate(self.secret_req)

        self.assertEqual(self.payload, result['payload'])

    def test_should_validate_future_expiration(self):
        self.secret_req['expiration'] = '2114-02-28T19:14:44.180394'
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertIsInstance(result['expiration'], datetime.datetime)

    def test_should_validate_future_expiration_no_t(self):
        self.secret_req['expiration'] = '2114-02-28 19:14:44.180394'
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertIsInstance(result['expiration'], datetime.datetime)

    def test_should_validate_expiration_with_z(self):
        expiration = '2114-02-28 19:14:44.180394Z'
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertIsInstance(result['expiration'], datetime.datetime)
        self.assertEqual(expiration[:-1], str(result['expiration']))

    def test_should_validate_expiration_with_tz(self):
        expiration = '2114-02-28 12:14:44.180394-05:00'
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertIsInstance(result['expiration'], datetime.datetime)
        expected = expiration[:-6].replace('12', '17', 1)
        self.assertEqual(expected, str(result['expiration']))

    def test_should_validate_expiration_extra_whitespace(self):
        expiration = '2114-02-28 12:14:44.180394-05:00      '
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertIsInstance(result['expiration'], datetime.datetime)
        expected = expiration[:-12].replace('12', '17', 1)
        self.assertEqual(expected, str(result['expiration']))

    def test_should_validate_empty_expiration(self):
        self.secret_req['expiration'] = '  '
        result = self.validator.validate(self.secret_req)

        self.assertIn('expiration', result)
        self.assertFalse(result['expiration'])

    def test_should_raise_numeric_name(self):
        self.secret_req['name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('name', exception.invalid_property)

    def test_should_raise_name_length_is_greater_than_max(self):
        self.secret_req['name'] = 'a' * 256
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('name', exception.invalid_property)

    def test_should_raise_negative_bit_length(self):
        self.secret_req['bit_length'] = -23

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)
        self.assertIn('bit_length', str(exception))

    def test_should_raise_non_integer_bit_length(self):
        self.secret_req['bit_length'] = "23"

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)
        self.assertIn('bit_length', str(exception))

    def test_should_raise_bit_length_less_than_min(self):
        self.secret_req['bit_length'] = 0

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)
        self.assertIn('bit_length', str(exception))

    def test_should_raise_bit_length_greater_than_max(self):
        self.secret_req['bit_length'] = 32768

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)
        self.assertIn('bit_length', str(exception))

    def test_should_raise_mode_length_greater_than_max(self):
        self.secret_req['mode'] = 'a' * 256

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('mode', exception.invalid_property)
        self.assertIn('mode', str(exception))

    def test_should_raise_mode_is_non_string(self):
        self.secret_req['mode'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('mode', exception.invalid_property)
        self.assertIn('mode', str(exception))

    def test_validation_should_raise_with_empty_payload(self):
        self.secret_req['payload'] = '   '

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload', exception.invalid_property)
        self.assertIn('payload', str(exception))

    def test_should_raise_already_expired(self):
        self.secret_req['expiration'] = '2004-02-28T19:14:44.180394'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)
        self.assertIn('expiration', str(exception))

    def test_should_raise_expiration_nonsense(self):
        self.secret_req['expiration'] = 'nonsense'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)
        self.assertIn('expiration', str(exception))

    def test_should_raise_expiration_is_non_string(self):
        self.secret_req['expiration'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)
        self.assertIn('expiration', str(exception))

    def test_should_raise_expiration_greater_than_max(self):
        self.secret_req['expiration'] = 'a' * 256

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)
        self.assertIn('expiration', str(exception))

    def test_should_raise_algorithm_is_non_string(self):
        self.secret_req['algorithm'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('algorithm', exception.invalid_property)
        self.assertIn('algorithm', str(exception))

    def test_should_raise_algorithm_greater_than_max(self):
        self.secret_req['algorithm'] = 'a' * 256

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('algorithm', exception.invalid_property)
        self.assertIn('algorithm', str(exception))

    def test_should_raise_all_nulls(self):
        self.secret_req = {'name': None,
                           'algorithm': None,
                           'bit_length': None,
                           'mode': None}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_all_empties(self):
        self.secret_req = {'name': '',
                           'algorithm': '',
                           'bit_length': '',
                           'mode': ''}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_no_payload_content_type(self):
        del self.secret_req['payload_content_type']

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_with_message_w_bad_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'plain/text'

        try:
            self.validator.validate(self.secret_req)
        except excep.InvalidObject as e:
            self.assertIsNotNone(e)
            self.assertIsNotNone(str(e))
        else:
            self.fail('No validation exception was raised')

    def test_should_validate_mixed_case_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TeXT/PlaiN'
        self.validator.validate(self.secret_req)

    def test_should_validate_upper_case_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TEXT/PLAIN'
        self.validator.validate(self.secret_req)

    def test_should_raise_with_mixed_case_wrong_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TeXT/PlaneS'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_with_upper_case_wrong_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TEXT/PLANE'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_payload_content_type_greater_than_max(self):
        self.secret_req['payload_content_type'] = 'a' * 256
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload_content_type', exception.invalid_property)
        self.assertIn('payload_content_type', str(exception))

    def test_should_raise_with_payload_content_encoding_greater_than_max(self):
        self.secret_req['payload_content_encoding'] = 'a' * 256
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload_content_encoding',
                         exception.invalid_property)
        self.assertIn('payload_content_encoding', str(exception))

    def test_should_raise_with_plain_text_and_encoding(self):
        self.secret_req['payload_content_encoding'] = 'base64'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_raise_with_wrong_encoding(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'unsupported'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_validate_with_supported_encoding(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'base64'
        self.secret_req['payload'] = 'bXktc2VjcmV0LWhlcmU='

        self.validator.validate(self.secret_req)

    def test_validation_should_validate_with_good_base64_payload(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'base64'
        self.secret_req['payload'] = 'bXktc2VjcmV0LWhlcmU='

        self.validator.validate(self.secret_req)

    def test_validation_should_raise_with_bad_base64_payload(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'base64'
        self.secret_req['payload'] = 'bad base 64'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload', exception.invalid_property)

    def test_validation_should_raise_with_unicode_payload(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'base64'
        self.secret_req['payload'] = chr(0x0080)

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload', exception.invalid_property)

    def test_should_pass_with_no_secret_type(self):
        request = dict(self.secret_req)
        del request['secret_type']
        self.validator.validate(request)

    def test_should_fail_with_unknown_secret_type(self):
        self.secret_req['secret_type'] = 'unknown_type'
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    @utils.parameterized_dataset({
        'symmetric': [get_symmetric_key_req()],
        'private': [get_private_key_req()],
        'public': [get_public_key_req()],
        'certificate': [get_certificate_req()],
        'passphrase': [get_passphrase_req()],
    })
    def test_should_pass_with_secret_type(self, request):
        self.validator.validate(request)

    @utils.parameterized_dataset({
        'symmetric': [get_symmetric_key_req(), 'foo'],
        'private': [get_private_key_req(), 'foo'],
        'public': [get_public_key_req(), 'foo'],
        'certificate': [get_certificate_req(), 'foo'],
        'passphrase': [get_passphrase_req(), 'base64'],
    })
    def test_should_fail_with_bad_encoding(self, request, content_encoding):
        request['payload_content_encoding'] = content_encoding
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            request,
        )

    @utils.parameterized_dataset({
        'symmetric': [get_symmetric_key_req(), 'text/plain'],
        'private': [get_private_key_req(), 'text/plain'],
        'public': [get_public_key_req(), 'text/plain'],
        'certificate': [get_certificate_req(), 'text/plain'],
        'passphrase': [get_passphrase_req(), 'application/octet-stream'],
    })
    def test_should_fail_with_bad_content_type(self, request, content_type):
        request['payload_content_type'] = content_type
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            request,
        )


class WhenTestingContainerValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingContainerValidator, self).setUp()

        validators.CONF.set_override("host_href", "http://localhost:9311")

        self.name = 'name'
        self.type = 'generic'
        self.secret_refs = [
            {
                'name': 'testname',
                'secret_ref': 'http://localhost:9311/1231'
            },
            {
                'name': 'testname2',
                'secret_ref': 'http://localhost:9311/1232'
            }
        ]

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

        self.validator = validators.ContainerValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.container_req)

    def test_should_validate_no_name(self):
        del self.container_req['name']
        self.validator.validate(self.container_req)

    def test_should_validate_empty_name(self):
        self.container_req['name'] = '    '
        self.validator.validate(self.container_req)

    def test_should_raise_name_length_greater_than_max(self):
        self.container_req['name'] = 'a' * 256

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )
        self.assertEqual('name', exception.invalid_property)
        self.assertIn('name', str(exception))

    def test_should_raise_nonstring_secret_name(self):
        self.secret_refs[0]["name"] = 5

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_secret_name_too_long(self):
        self.secret_refs[0]['name'] = 'a' * 256

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )
        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_numeric_name(self):
        self.container_req['name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('name', exception.invalid_property)
        self.assertIn('name', exception.message)

    def test_should_raise_no_type(self):
        del self.container_req['type']

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertIn('type', str(exception))

    def test_should_raise_empty_type(self):
        self.container_req['type'] = ''

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('type', exception.invalid_property)

    def test_should_raise_not_supported_type(self):
        self.container_req['type'] = 'testtype'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('type', exception.invalid_property)

    def test_should_raise_all_nulls(self):
        self.container_req = {'name': None,
                              'type': None,
                              'bit_length': None,
                              'secret_refs': None}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_raise_all_empties(self):
        self.container_req = {'name': '',
                              'type': '',
                              'secret_refs': []}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_validate_empty_secret_refs(self):
        self.container_req['secret_refs'] = []
        self.validator.validate(self.container_req)

    def test_should_raise_no_secret_ref_in_secret_refs(self):
        del self.container_req['secret_refs'][0]['secret_ref']

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_raise_empty_secret_ref_in_secret_refs(self):
        self.container_req['secret_refs'][0]['secret_ref'] = ''

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_raise_numeric_secret_ref_in_secret_refs(self):
        self.container_req['secret_refs'][0]['secret_ref'] = 123

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_raise_duplicate_names_in_secret_refs(self):
        self.container_req['secret_refs'].append(
            self.container_req['secret_refs'][0])

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_duplicate_secret_ids_in_secret_refs(self):

        secret_ref = self.container_req['secret_refs'][0]
        secret_ref['name'] = 'testname3'
        self.container_req['secret_refs'].append(secret_ref)

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_duplicate_secret_ref_format_ids_in_secret_refs(self):
        """Test duplicate secret_id presence as part of single container.

           Here secret_id is represented in different format and secret_id is
           extracted from there.
        """

        secret_refs = [
            {
                'name': 'testname',
                'secret_ref': 'http://localhost:9311/v1/12345/secrets/1231'
            },
            {
                'name': 'testname2',
                'secret_ref': 'http://localhost:9311/v1/12345/secrets//1232'
            },
            {
                'name': 'testname3',
                'secret_ref': 'http://localhost:9311/v1/12345/secrets//1231/'

            }
        ]

        container_req = {'name': 'name',
                         'type': 'generic',
                         'secret_refs': secret_refs}

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_ensure_unconfigured_secret_ref_hostname_cannot_be_passed_in(self):
        # Attempt to add some bogus secret refs.
        secret_refs = [
            {
                'name': 'super-secret-beer-ingredient',
                'secret_ref': 'http://kegsarecool.com:9311/1234/secrets/57890'
            },
            {
                'name': 'iShouldNotBeAbleToExist',
                'secret_ref': 'http://invalid.fqdn:9311/v1/secrets/FAD23'
            }
        ]
        container_req = {
            'name': 'test-container',
            'type': 'generic',
            'secret_refs': secret_refs
        }
        self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            container_req,
        )

    def test_ensure_secret_ref_starts_with_request_hostname(self):
        # Attempt to add some bogus secret refs.
        secret_refs = [
            {
                'name': 'pass_malicious_hostname',
                'secret_ref': 'http://www.malicious.com:8080/spoofForToken?'
                'dummy=http://localhost:9311'
            },
        ]
        container_req = {
            'name': 'test-container',
            'type': 'generic',
            'secret_refs': secret_refs
        }
        self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            container_req,
        )


class WhenTestingRSAContainerValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingRSAContainerValidator, self).setUp()

        validators.CONF.set_override("host_href", "http://localhost:9311")

        self.name = 'name'
        self.type = 'rsa'
        self.secret_refs = [
            {
                'name': 'public_key',
                'secret_ref': 'http://localhost:9311/1231'
            },
            {
                'name': 'private_key',
                'secret_ref': 'http://localhost:9311/1232'
            },
            {
                'name': 'private_key_passphrase',
                'secret_ref': 'http://localhost:9311/1233'
            }
        ]

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

        self.validator = validators.ContainerValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.container_req)

    def test_should_raise_no_names_in_secret_refs(self):
        del self.container_req['secret_refs'][0]['name']

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_empty_names_in_secret_refs(self):
        self.container_req['secret_refs'][0]['name'] = ''

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_unsupported_names_in_secret_refs(self):
        self.container_req['secret_refs'][0]['name'] = 'testttt'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_duplicate_secret_id_in_secret_refs(self):
        self.container_req['secret_refs'][0]['secret_ref'] = (
            self.container_req['secret_refs'][2]['secret_ref'])

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_more_than_3_secret_refs_for_rsa_type(self):
        new_secret_ref = {
            'name': 'new secret ref',
            'secret_ref': 'http://localhost:9311/234234'
        }
        self.container_req['secret_refs'].append(new_secret_ref)

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_if_required_name_missing(self):
        name = 'name'
        type = 'certificate'
        secret_refs = [
            {
                'name': 'private_key',
                'secret_ref': 'http://localhost:9311/123'
            },
            {
                'name': 'private_key_passphrase',
                'secret_ref': 'http://localhost:9311/123'
            }
        ]
        container_req = {'name': name, 'type': type,
                         'secret_refs': secret_refs}
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            container_req)
        self.assertEqual('secret_refs', exception.invalid_property)


class WhenTestingCertificateContainerValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingCertificateContainerValidator, self).setUp()

        validators.CONF.set_override("host_href", "http://localhost:9311")

        self.name = 'name'
        self.type = 'certificate'
        self.secret_refs = [
            {
                'name': 'certificate',
                'secret_ref': 'http://localhost:9311/S4dfsdrf'
            },
            {
                'name': 'private_key',
                'secret_ref': 'http://localhost:9311/1231'
            },
            {
                'name': 'private_key_passphrase',
                'secret_ref': 'http://localhost:9311/1232'
            },
            {
                'name': 'intermediates',
                'secret_ref': 'http://localhost:9311/1233'
            }
        ]

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

        self.validator = validators.ContainerValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.container_req)

    def test_should_raise_more_than_4_secret_refs_for_cert_type(self):
        new_secret_ref = {
            'name': 'new secret ref',
            'secret_ref': 'http://localhost:9311/234234'
        }
        self.container_req['secret_refs'].append(new_secret_ref)

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req)
        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_unsupported_names_in_secret_refs(self):
        self.container_req['secret_refs'][0]['name'] = 'public_key'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req)
        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_raise_if_required_name_missing(self):
        name = 'name'
        type = 'certificate'
        secret_refs = [
            {
                'name': 'private_key',
                'secret_ref': '123'
            },
            {
                'name': 'intermediates',
                'secret_ref': '123'
            }
        ]
        container_req = {'name': name, 'type': type,
                         'secret_refs': secret_refs}
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            container_req)
        self.assertEqual('secret_refs', exception.invalid_property)


class WhenTestingTransportKeyValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingTransportKeyValidator, self).setUp()

        self.plugin_name = 'name'
        self.transport_key = 'abcdef'
        self.transport_req = {'plugin_name': self.plugin_name,
                              'transport_key': self.transport_key}

        self.validator = validators.NewTransportKeyValidator()

    def test_should_raise_with_invalid_json_data_type(self):
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            []
        )

    def test_should_raise_with_empty_transport_key(self):
        self.transport_req['transport_key'] = ''

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.transport_req
        )

        self.assertEqual('transport_key', exception.invalid_property)

    def test_should_raise_transport_key_is_non_string(self):
        self.transport_req['transport_key'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.transport_req
        )

        self.assertEqual('transport_key', exception.invalid_property)

    def test_should_raise_transport_key_is_missing(self):
        del self.transport_req['transport_key']

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.transport_req
        )

        self.assertEqual('transport_key', exception.invalid_property)

    def test_should_raise_plugin_name_is_non_string(self):
        self.transport_req['plugin_name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.transport_req
        )

        self.assertEqual('plugin_name', exception.invalid_property)

    def test_should_raise_plugin_name_is_missing(self):
        del self.transport_req['plugin_name']

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.transport_req
        )

        self.assertEqual('plugin_name', exception.invalid_property)


class WhenTestingConsumerValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingConsumerValidator, self).setUp()

        self.name = 'name'
        self.URL = 'http://my.url/resource/UUID'
        self.consumer_req = {'name': self.name,
                             'URL': self.URL}
        self.validator = validators.ContainerConsumerValidator()

    def test_should_raise_with_invalid_json_data_type(self):
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            []
        )

    def test_should_raise_with_missing_name(self):
        consumer_req = {'URL': self.URL}
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            consumer_req
        )

        self.assertIn('\'name\'', exception.args[0])

    def test_should_raise_with_missing_URL(self):
        consumer_req = {'name': self.name}

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            consumer_req
        )

        self.assertIn('\'URL\'', exception.args[0])

    def test_should_validate_all_fields(self):
        self.validator.validate(self.consumer_req)

    def test_name_too_long_should_raise_with_invalid_object(self):
        # Negative test to make sure our maxLength parameter for the
        # name field raises the proper exception when a value greater
        # than 255 in this case is passed in.
        longname = 'a' * 256
        consumer_req = {'name': longname, 'url': self.URL}
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            consumer_req
        )


class WhenTestingKeyTypeOrderValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingKeyTypeOrderValidator, self).setUp()
        self.type = 'key'
        self.meta = {"name": "secretname",
                     "algorithm": "AES",
                     "bit_length": 256,
                     "mode": "cbc"}

        self.key_order_req = {'type': self.type,
                              'meta': self.meta}

        self.validator = validators.TypeOrderValidator()

    def test_should_pass_with_null_content_type_in_meta(self):
        self.key_order_req['meta']['payload_content_type'] = None
        result = self.validator.validate(self.key_order_req)
        self.assertIsNone(result['meta']['payload_content_type'])

    def test_should_pass_good_bit_meta_in_order_refs(self):
        self.key_order_req['meta']['algorithm'] = 'AES'
        self.key_order_req['meta']['bit_length'] = 256
        result = self.validator.validate(self.key_order_req)
        self.assertIsNone(result['meta']['expiration'])

    def test_should_pass_good_exp_meta_in_order_refs(self):
        self.key_order_req['meta']['algorithm'] = 'AES'
        ony_year_factor = datetime.timedelta(days=1 * 365)
        date_after_year = timeutils.utcnow() + ony_year_factor
        date_after_year_str = date_after_year.strftime('%Y-%m-%d %H:%M:%S')
        self.key_order_req['meta']['expiration'] = date_after_year_str
        result = self.validator.validate(self.key_order_req)

        self.assertIn('expiration', result['meta'])
        self.assertIsInstance(result['meta']['expiration'],
                              datetime.datetime)

    def test_should_raise_with_no_type_in_order_refs(self):
        del self.key_order_req['type']

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('type', exception.invalid_property)

    def test_should_raise_with_bad_type_in_order_refs(self):
        self.key_order_req['type'] = 'badType'

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('type', exception.invalid_property)

    def test_should_raise_with_no_meta_in_order_refs(self):
        del self.key_order_req['meta']

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('meta', exception.invalid_property)

    def test_should_raise_with_no_algorithm_in_order_refs(self):
        del self.key_order_req['meta']['algorithm']

        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.key_order_req)

    def test_should_raise_with_no_bit_length_in_order_refs(self):
        del self.key_order_req['meta']['bit_length']

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertIn("bit_length' is required field for key type order",
                      str(exception))

    def test_should_raise_with_zero_bit_length_in_order_refs(self):
        self.key_order_req['meta']['bit_length'] = 0

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('bit_length', exception.invalid_property)

    def test_should_raise_with_negative_bit_length_in_order_refs(self):
        self.key_order_req['meta']['bit_length'] = -1

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('bit_length', exception.invalid_property)

    def test_should_raise_with_wrong_exp_meta_in_order_refs(self):
        self.key_order_req['meta']['algorithm'] = 'AES'
        self.key_order_req['meta']['expiration'] = '2014-02-28T19:14:44.180394'

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.key_order_req)
        self.assertEqual('expiration', exception.invalid_property)

    def test_should_not_raise_correct_hmac_order_refs(self):
        self.key_order_req['meta']['algorithm'] = 'hmacsha1'
        del self.key_order_req['meta']['mode']

        result = self.validator.validate(self.key_order_req)
        self.assertIsNotNone(result)
        self.assertEqual('hmacsha1', result['meta']['algorithm'])

    def test_should_raise_with_payload_in_order(self):
        self.key_order_req['meta']['payload'] = 'payload'
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.key_order_req)


class WhenTestingAsymmetricTypeOrderValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingAsymmetricTypeOrderValidator, self).setUp()
        self.type = 'asymmetric'
        self.meta = {"name": "secretname",
                     "algorithm": "RSA",
                     "bit_length": 256}

        self.asymmetric_order_req = {'type': self.type,
                                     'meta': self.meta}

        self.validator = validators.TypeOrderValidator()

    def test_should_pass_good_meta_in_order_refs(self):
        result = self.validator.validate(self.asymmetric_order_req)
        self.assertIsNone(result['meta']['expiration'])

    def test_should_raise_with_no_algorithm_in_order_refs(self):
        del self.asymmetric_order_req['meta']['algorithm']

        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.asymmetric_order_req)

    def test_should_raise_with_payload_in_order(self):
        self.asymmetric_order_req['meta']['payload'] = 'payload'
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.asymmetric_order_req)

    def test_should_pass_with_wrong_algorithm_in_asymmetric_order_refs(self):
        # Note (atiwari): because validator should not check
        # algorithm but that should checked at crypto_plugin
        # supports method.
        self.asymmetric_order_req['meta']['algorithm'] = 'aes'
        result = self.validator.validate(self.asymmetric_order_req)
        self.assertIsNone(result['meta']['expiration'])

    def test_should_raise_with_no_bit_length_in_asymmetric_order_refs(self):
        del self.asymmetric_order_req['meta']['bit_length']

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.asymmetric_order_req)
        self.assertIn(
            "bit_length' is required field for asymmetric key type order",
            str(exception))

    def test_should_raise_with_zero_bit_length_in_asymmetric_order_refs(self):
        self.asymmetric_order_req['meta']['bit_length'] = 0

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.asymmetric_order_req)
        self.assertEqual("bit_length", exception.invalid_property)

    def test_should_raise_with_negative_bit_len_in_asymmetric_order_refs(self):
        self.asymmetric_order_req['meta']['bit_length'] = -1

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.asymmetric_order_req)
        self.assertEqual("bit_length", exception.invalid_property)


@utils.parameterized_test_case
class WhenTestingAclValidator(utils.BaseTestCase):
    def setUp(self):
        super(WhenTestingAclValidator, self).setUp()
        self.validator = validators.ACLValidator()

    @utils.parameterized_dataset({
        'one_reader': [{'read': {'users': ['reader'],
                                 'project-access': True}}],
        'two_reader': [{'read': {'users': ['r1', 'r2'],
                                 'project-access': True}}],
        'private': [{'read': {'users': [], 'project-access': False}}],
        'default_users': [{'read': {'project-access': False}}],
        'default_creator': [{'read': {'users': ['reader']}}],
        'almost_empty': [{'read': {}}],
        'empty': [{}],
    })
    def test_should_validate(self, acl_req):
        self.validator.validate(acl_req)

    @utils.parameterized_dataset({
        'foo': ['foo'],
        'bad_op': [{'bad_op': {'users': ['reader'], 'project-access': True}}],
        'bad_field': [{'read': {'bad_field': ['reader'],
                                'project-access': True}}],
        'bad_user': [{'read': {'users': [27], 'project-access': True}}],
        'missing_op': [{'project-access': False}],
    })
    def test_should_raise(self, acl_req):
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          acl_req)

    @utils.parameterized_dataset({
        'write': [{'write': {'users': ['writer'], 'project-access': True}}],
        'list': [{'list': {'users': ['lister'], 'project-access': True}}],
        'delete': [{'delete': {'users': ['deleter'], 'project-access': True}}],
    })
    def test_should_raise_future(self, acl_req):
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          acl_req)


class WhenTestingProjectQuotasValidator(utils.BaseTestCase):
    def setUp(self):
        super(WhenTestingProjectQuotasValidator, self).setUp()
        self.good_project_quotas = {"project_quotas":
                                    {"secrets": 50,
                                     "orders": 10,
                                     "containers": 20,
                                     "cas": 30}}
        self.bad_project_quotas = {"bad key": "bad value"}
        self.validator = validators.ProjectQuotaValidator()

    def test_should_pass_good_data(self):
        self.validator.validate(self.good_project_quotas)

    def test_should_pass_empty_properties(self):
        self.validator.validate({"project_quotas": {}})

    def test_should_raise_bad_data(self):
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.bad_project_quotas)

    def test_should_raise_empty_dict(self):
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          {})

    def test_should_raise_secrets_non_int(self):
        self.good_project_quotas['project_quotas']['secrets'] = "abc"
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.good_project_quotas)

    def test_should_raise_orders_non_int(self):
        self.good_project_quotas['project_quotas']['orders'] = "abc"
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.good_project_quotas)

    def test_should_raise_containers_non_int(self):
        self.good_project_quotas['project_quotas']['containers'] = "abc"
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.good_project_quotas)

    def test_should_raise_cas_non_int(self):
        self.good_project_quotas['project_quotas']['cas'] = "abc"
        self.assertRaises(excep.InvalidObject,
                          self.validator.validate,
                          self.good_project_quotas)


@utils.parameterized_test_case
class WhenTestingSecretMetadataValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMetadataValidator, self).setUp()

        self.top_key = 'metadata'

        self.key1 = 'city'
        self.value1 = 'Austin'

        self.key2 = 'state'
        self.value2 = 'Texas'

        self.key3 = 'country'
        self.value3 = 'USA'

        self.metadata_req = {
            self.top_key: {
                self.key1: self.value1,
                self.key2: self.value2,
                self.key3: self.value3
            }
        }

        self.validator = validators.NewSecretMetadataValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.metadata_req)

    def test_should_validate_all_fields_and_make_key_lowercase(self):
        self.key1 = "DOgg"
        self.value1 = "poodle"
        self.metadata_req = {
            self.top_key: {
                self.key1: self.value1,
                self.key2: self.value2,
                self.key3: self.value3
            }
        }
        metadata = self.validator.validate(self.metadata_req)
        self.assertNotIn("DOgg", metadata.keys())
        self.assertIn("dogg", metadata.keys())

    def test_should_validate_no_keys(self):
        del self.metadata_req[self.top_key][self.key1]
        del self.metadata_req[self.top_key][self.key2]
        del self.metadata_req[self.top_key][self.key3]
        self.validator.validate(self.metadata_req)

    def test_should_raise_invalid_key_no_metadata(self):
        del self.metadata_req[self.top_key]
        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.metadata_req)
        self.assertIn("metadata' is a required property",
                      str(exception))

    def test_should_raise_invalid_key_non_string(self):
        self.key1 = 0
        metadata_req = {
            self.top_key: {
                self.key1: self.value1
            }
        }
        exception = self.assertRaises(excep.InvalidMetadataRequest,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Invalid Metadata. Keys and Values must be Strings.",
                      str(exception))

    def test_should_raise_invalid_key_non_url_safe_string(self):
        self.key1 = "key/01"
        metadata_req = {
            self.top_key: {
                self.key1: self.value1
            }
        }
        exception = self.assertRaises(excep.InvalidMetadataKey,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Invalid Key. Key must be URL safe.",
                      str(exception))

    def test_should_raise_invalid_value_non_string(self):
        self.value1 = 0
        metadata_req = {
            self.top_key: {
                self.key1: self.value1
            }
        }
        exception = self.assertRaises(excep.InvalidMetadataRequest,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Invalid Metadata. Keys and Values must be Strings.",
                      str(exception))


@utils.parameterized_test_case
class WhenTestingSecretMetadatumValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMetadatumValidator, self).setUp()

        self.key1 = 'key'
        self.value1 = 'city'

        self.key2 = 'value'
        self.value2 = 'Austin'

        self.metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2
        }

        self.validator = validators.NewSecretMetadatumValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.metadata_req)

    def test_should_validate_all_fields_and_make_key_lowercase(self):
        self.value1 = "DOgg"
        self.value2 = "poodle"
        self.metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2
        }
        metadata = self.validator.validate(self.metadata_req)
        self.assertEqual("dogg", metadata['key'])

    def test_should_raise_invalid_empty(self):
        del self.metadata_req[self.key1]
        del self.metadata_req[self.key2]
        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))

    def test_should_raise_invalid_key_no_key(self):
        del self.metadata_req[self.key2]
        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))

    def test_should_raise_invalid_key_no_value(self):
        del self.metadata_req[self.key1]
        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      self.metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))

    def test_should_raise_invalid_key_non_string(self):
        self.value1 = 0
        metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2
        }

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))

    def test_should_raise_invalid_key_non_url_safe_string(self):
        self.value1 = "key/01"
        metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2
        }

        exception = self.assertRaises(excep.InvalidMetadataKey,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Invalid Key. Key must be URL safe.",
                      str(exception))

    def test_should_raise_invalid_value_non_string(self):
        self.value2 = 0
        metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2
        }

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))

    def test_should_raise_invalid_extra_sent_key(self):
        self.value2 = 0
        metadata_req = {
            self.key1: self.value1,
            self.key2: self.value2,
            "extra_key": "extra_value"
        }

        exception = self.assertRaises(excep.InvalidObject,
                                      self.validator.validate,
                                      metadata_req)
        self.assertIn("Provided object does not match schema "
                      "'SecretMetadatum'",
                      str(exception))


class WhenTestingSecretConsumerValidator(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretConsumerValidator, self).setUp()

        self.service = "service"
        self.resource_type = "resource_type"
        self.resource_id = "resource_id"
        self.consumer_req = {
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
        }
        self.validator = validators.SecretConsumerValidator()

    def test_should_raise_with_invalid_json_data_type(self):
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            []
        )

    def test_should_raise_with_missing_service(self):
        self.consumer_req.pop("service")
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.consumer_req
        )

        self.assertIn('\'service\'', exception.args[0])

    def test_should_raise_with_missing_resource_type(self):
        self.consumer_req.pop("resource_type")
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.consumer_req
        )

        self.assertIn('\'resource_type\'', exception.args[0])

    def test_should_raise_with_missing_resource_id(self):
        self.consumer_req.pop("resource_id")
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.consumer_req
        )

        self.assertIn('\'resource_id\'', exception.args[0])

    def test_should_validate_all_fields(self):
        self.validator.validate(self.consumer_req)

    def test_service_too_long_should_raise_with_invalid_object(self):
        # Negative test to make sure our maxLength parameter for the
        # service field raises the proper exception when a value greater
        # than 255 in this case is passed in.
        self.consumer_req["service"] = 'a' * 256
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.consumer_req
        )

    def test_resource_type_too_long_should_raise_with_invalid_object(self):
        # Negative test to make sure our maxLength parameter for the
        # service field raises the proper exception when a value greater
        # than 255 in this case is passed in.
        self.consumer_req["resource_type"] = 'a' * 256
        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.consumer_req
        )


if __name__ == '__main__':
    unittest.main()
