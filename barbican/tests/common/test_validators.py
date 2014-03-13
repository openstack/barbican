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

import unittest
import datetime

import testtools

from barbican.common import exception as excep
from barbican.common import validators


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingSecretValidator())

    return suite


class WhenTestingSecretValidator(testtools.TestCase):

    def setUp(self):
        super(WhenTestingSecretValidator, self).setUp()

        self.name = 'name'
        self.payload = b'not-encrypted'
        self.payload_content_type = 'text/plain'
        self.secret_algorithm = 'algo'
        self.secret_bit_length = 512
        self.secret_mode = 'cytype'

        self.secret_req = {'name': self.name,
                           'payload_content_type': self.payload_content_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
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

    def test_should_validate_no_payload(self):
        del self.secret_req['payload']
        del self.secret_req['payload_content_type']
        result = self.validator.validate(self.secret_req)

        self.assertFalse('payload' in result)

    def test_should_validate_payload_with_whitespace(self):
        self.secret_req['payload'] = '  ' + self.payload + '    '
        result = self.validator.validate(self.secret_req)

        self.assertEqual(self.payload, result['payload'])

    def test_should_validate_future_expiration(self):
        self.secret_req['expiration'] = '2114-02-28T19:14:44.180394'
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))

    def test_should_validate_future_expiration_no_t(self):
        self.secret_req['expiration'] = '2114-02-28 19:14:44.180394'
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))

    def test_should_validate_expiration_with_z(self):
        expiration = '2114-02-28 19:14:44.180394Z'
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))
        self.assertEqual(expiration[:-1], str(result['expiration']))

    def test_should_validate_expiration_with_tz(self):
        expiration = '2114-02-28 12:14:44.180394-05:00'
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))
        expected = expiration[:-6].replace('12', '17', 1)
        self.assertEqual(expected, str(result['expiration']))

    def test_should_validate_expiration_extra_whitespace(self):
        expiration = '2114-02-28 12:14:44.180394-05:00      '
        self.secret_req['expiration'] = expiration
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))
        expected = expiration[:-12].replace('12', '17', 1)
        self.assertEqual(expected, str(result['expiration']))

    def test_should_validate_empty_expiration(self):
        self.secret_req['expiration'] = '  '
        result = self.validator.validate(self.secret_req)

        self.assertTrue('expiration' in result)
        self.assertTrue(not result['expiration'])

    def test_should_fail_numeric_name(self):
        self.secret_req['name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('name', exception.invalid_property)

    def test_should_fail_negative_bit_length(self):
        self.secret_req['bit_length'] = -23

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)

    def test_should_fail_non_integer_bit_length(self):
        self.secret_req['bit_length'] = "23"

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('bit_length', exception.invalid_property)

    def test_validation_should_fail_with_empty_payload(self):
        self.secret_req['payload'] = '   '

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('payload', exception.invalid_property)

    def test_should_fail_already_expired(self):
        self.secret_req['expiration'] = '2004-02-28T19:14:44.180394'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)

    def test_should_fail_expiration_nonsense(self):
        self.secret_req['expiration'] = 'nonsense'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )
        self.assertEqual('expiration', exception.invalid_property)

    def test_should_fail_all_nulls(self):
        self.secret_req = {'name': None,
                           'algorithm': None,
                           'bit_length': None,
                           'mode': None}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_all_empties(self):
        self.secret_req = {'name': '',
                           'algorithm': '',
                           'bit_length': '',
                           'mode': ''}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_no_payload_content_type(self):
        del self.secret_req['payload_content_type']

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_with_message_w_bad_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'plain/text'

        try:
            self.validator.validate(self.secret_req)
        except excep.InvalidObject as e:
            self.assertNotEqual(str(e), 'None')
            self.assertIsNotNone(e.message)
            self.assertNotEqual(e.message, 'None')
        else:
            self.fail('No validation exception was raised')

    def test_should_validate_mixed_case_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TeXT/PlaiN'
        self.validator.validate(self.secret_req)

    def test_should_validate_upper_case_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TEXT/PLAIN'
        self.validator.validate(self.secret_req)

    def test_should_fail_with_mixed_case_wrong_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TeXT/PlaneS'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_with_upper_case_wrong_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'TEXT/PLANE'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_with_plain_text_and_encoding(self):
        self.secret_req['payload_content_encoding'] = 'base64'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_fail_with_wrong_encoding(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'unsupported'

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

    def test_should_validate_with_wrong_encoding(self):
        self.secret_req['payload_content_type'] = 'application/octet-stream'
        self.secret_req['payload_content_encoding'] = 'base64'

        self.validator.validate(self.secret_req)


class WhenTestingOrderValidator(testtools.TestCase):

    def setUp(self):
        super(WhenTestingOrderValidator, self).setUp()

        self.name = 'name'
        self.secret_algorithm = 'aes'
        self.secret_bit_length = 128
        self.secret_mode = 'cbc'
        self.secret_payload_content_type = 'application/octet-stream'

        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload_content_type':
                           self.secret_payload_content_type}
        self.order_req = {'secret': self.secret_req}

        self.validator = validators.NewOrderValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.order_req)

    def test_should_validate_no_name(self):
        del self.secret_req['name']
        result = self.validator.validate(self.order_req)

        self.assertTrue('secret' in result)

    def test_should_validate_empty_name(self):
        self.secret_req['name'] = '    '
        result = self.validator.validate(self.order_req)

        self.assertTrue('secret' in result)

    def test_should_validate_future_expiration(self):
        self.secret_req['expiration'] = '2114-02-28T19:14:44.180394'
        result = self.validator.validate(self.order_req)

        self.assertTrue('secret' in result)
        result = result['secret']
        self.assertTrue('expiration' in result)
        self.assertTrue(isinstance(result['expiration'], datetime.datetime))

    def test_should_validate_empty_expiration(self):
        self.secret_req['expiration'] = '  '
        result = self.validator.validate(self.order_req)

        self.assertTrue('secret' in result)
        result = result['secret']
        self.assertTrue('expiration' in result)
        self.assertTrue(not result['expiration'])

    def test_should_fail_numeric_name(self):
        self.secret_req['name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('name', exception.invalid_property)

    def test_should_fail_bad_mode(self):
        self.secret_req['mode'] = 'badmode'

        exception = self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('mode', exception.invalid_field)

    def test_should_fail_negative_bit_length(self):
        self.secret_req['bit_length'] = -23

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('bit_length', exception.invalid_property)

    def test_should_fail_non_integer_bit_length(self):
        self.secret_req['bit_length'] = "23"

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('bit_length', exception.invalid_property)

    def test_should_fail_non_multiple_eight_bit_length(self):
        self.secret_req['bit_length'] = 129

        exception = self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('bit_length', exception.invalid_field)

    def test_should_fail_secret_not_order_schema_provided(self):
        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.secret_req,
        )

        self.assertEqual('secret', exception.invalid_property)

    def test_should_fail_payload_provided(self):
        self.secret_req['payload'] = '  '

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertTrue('payload' in exception.invalid_property)

    def test_should_fail_already_expired(self):
        self.secret_req['expiration'] = '2004-02-28T19:14:44.180394'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('expiration', exception.invalid_property)

    def test_should_fail_expiration_nonsense(self):
        self.secret_req['expiration'] = 'nonsense'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('expiration', exception.invalid_property)

    def test_should_fail_all_nulls(self):
        self.secret_req = {'name': None,
                           'algorithm': None,
                           'bit_length': None,
                           'mode': None}
        self.order_req = {'secret': self.secret_req}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

    def test_should_fail_all_empties(self):
        self.secret_req = {'name': '',
                           'algorithm': '',
                           'bit_length': '',
                           'mode': ''}
        self.order_req = {'secret': self.secret_req}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.order_req,
        )

    def test_should_fail_no_payload_content_type(self):
        del self.secret_req['payload_content_type']

        self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

    def test_should_fail_unsupported_payload_content_type(self):
        self.secret_req['payload_content_type'] = 'text/plain'

        self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

    def test_should_fail_empty_mode(self):
        del self.secret_req['mode']

        exception = self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('mode', exception.invalid_field)

    def test_should_fail_empty_algorithm(self):
        del self.secret_req['algorithm']

        exception = self.assertRaises(
            excep.UnsupportedField,
            self.validator.validate,
            self.order_req,
        )

        self.assertEqual('algorithm', exception.invalid_field)


class WhenTestingContainerValidator(testtools.TestCase):

    def setUp(self):
        super(WhenTestingContainerValidator, self).setUp()

        self.name = 'name'
        self.type = 'generic'
        self.secret_refs = [
            {
                'name': 'testname',
                'secret_ref': '123'
            },
            {
                'name': 'testname2',
                'secret_ref': '123'
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

    def test_should_fail_no_type(self):
        del self.container_req['type']

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        #TODO: (hgedikli) figure out why invalid_property is null here
        #self.assertEqual('type', e.exception.invalid_property)

    def test_should_fail_empty_type(self):
        self.container_req['type'] = ''

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('type', exception.invalid_property)

    def test_should_fail_not_supported_type(self):
        self.container_req['type'] = 'testtype'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('type', exception.invalid_property)

    def test_should_fail_numeric_name(self):
        self.container_req['name'] = 123

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('name', exception.invalid_property)

    def test_should_fail_all_nulls(self):
        self.container_req = {'name': None,
                              'type': None,
                              'bit_length': None,
                              'secret_refs': None}

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_fail_all_empties(self):
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

    def test_should_fail_no_secret_ref_in_secret_refs(self):
        del self.container_req['secret_refs'][0]['secret_ref']

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_fail_empty_secret_ref_in_secret_refs(self):
        self.container_req['secret_refs'][0]['secret_ref'] = ''

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_fail_numeric_secret_ref_in_secret_refs(self):
        self.container_req['secret_refs'][0]['secret_ref'] = 123

        self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

    def test_should_fail_duplicate_names_in_secret_refs(self):
        self.container_req['secret_refs'].append(
            self.container_req['secret_refs'][0])

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)


class WhenTestingRSAContainerValidator(testtools.TestCase):

    def setUp(self):
        super(WhenTestingRSAContainerValidator, self).setUp()

        self.name = 'name'
        self.type = 'rsa'
        self.secret_refs = [
            {
                'name': 'public_key',
                'secret_ref': '123'
            },
            {
                'name': 'private_key',
                'secret_ref': '123'
            },
            {
                'name': 'private_key_passphrase',
                'secret_ref': '123'
            }
        ]

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

        self.validator = validators.ContainerValidator()

    def test_should_fail_no_names_in_secret_refs(self):
        del self.container_req['secret_refs'][0]['name']

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_fail_empty_names_in_secret_refs(self):
        self.container_req['secret_refs'][0]['name'] = ''

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_fail_unsupported_names_in_secret_refs(self):
        self.container_req['secret_refs'][0]['name'] = 'testttt'

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)

    def test_should_fail_more_than_3_secret_refs(self):
        new_secret_ref = {
            'name': 'new secret ref',
            'secret_ref': '234234'
        }
        self.container_req['secret_refs'].append(new_secret_ref)

        exception = self.assertRaises(
            excep.InvalidObject,
            self.validator.validate,
            self.container_req,
        )

        self.assertEqual('secret_refs', exception.invalid_property)


if __name__ == '__main__':
    unittest.main()
