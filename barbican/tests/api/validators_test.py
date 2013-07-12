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

import unittest
import datetime
from barbican.common import exception as excep
from barbican.common import validators


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingSecretValidator())

    return suite


class WhenTestingSecretValidator(unittest.TestCase):

    def setUp(self):
        self.name = 'name'
        self.plain_text = 'not-encrypted'.decode('utf-8')
        self.mime_type = 'text/plain'
        self.secret_algorithm = 'algo'
        self.secret_bit_length = 512
        self.secret_cypher_type = 'cytype'

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': self.plain_text}

        self.validator = validators.NewSecretValidator()

    def test_should_validate_all_fields(self):
        self.validator.validate(self.secret_req)

    def test_should_validate_no_name(self):
        del self.secret_req['name']
        self.validator.validate(self.secret_req)

    def test_should_validate_empty_name(self):
        self.secret_req['name'] = '    '
        self.validator.validate(self.secret_req)

    def test_should_validate_no_plain_text(self):
        del self.secret_req['plain_text']
        result = self.validator.validate(self.secret_req)

        self.assertFalse('plain_text' in result)

    def test_should_validate_plain_text_with_whitespace(self):
        self.secret_req['plain_text'] = '  ' + self.plain_text + '    '
        result = self.validator.validate(self.secret_req)

        self.assertEqual(self.plain_text, result['plain_text'])

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

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('name' in str(exception))

    def test_should_fail_no_mime(self):
        del self.secret_req['mime_type']

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_negative_bit_length(self):
        self.secret_req['bit_length'] = -23

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('bit_length' in str(exception))

    def test_should_fail_non_integer_bit_length(self):
        self.secret_req['bit_length'] = "23"

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('bit_length' in str(exception))

    def test_should_fail_empty_plain_text(self):
        self.secret_req['plain_text'] = '   '

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('plain_text' in str(exception))

    def test_should_fail_bad_mime(self):
        self.secret_req['mime_type'] = 'badmime'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_already_expired(self):
        self.secret_req['expiration'] = '2004-02-28T19:14:44.180394'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('expiration' in str(exception))

    def test_should_fail_expiration_nonsense(self):
        self.secret_req['expiration'] = 'nonsense'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('expiration' in str(exception))

    def test_should_fail_all_nulls(self):
        self.secret_req = {'name': None,
                           'algorithm': None,
                           'bit_length': None,
                           'cypher_type': None}

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_all_empties(self):
        self.secret_req = {'name': '',
                           'algorithm': '',
                           'bit_length': '',
                           'cypher_type': ''}

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))


class WhenTestingOrderValidator(unittest.TestCase):

    def setUp(self):
        self.name = 'name'
        self.mime_type = 'application/octet-stream'
        self.secret_algorithm = 'aes'
        self.secret_bit_length = 128
        self.secret_cypher_type = 'cbc'

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type}
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

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('name' in str(exception))

    def test_should_fail_bad_cypher_type(self):
        self.secret_req['cypher_type'] = 'badcypher'

        with self.assertRaises(excep.UnsupportedField) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('cypher_type' in str(exception))

    def test_should_fail_no_mime(self):
        del self.secret_req['mime_type']

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_bad_mime(self):
        self.secret_req['mime_type'] = 'badmimehere'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_wrong_mime(self):
        self.secret_req['mime_type'] = 'text/plain'

        with self.assertRaises(excep.UnsupportedField) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_bad_mime_empty(self):
        self.secret_req['mime_type'] = ''

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_bad_mime_whitespace(self):
        self.secret_req['mime_type'] = '   '

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_negative_bit_length(self):
        self.secret_req['bit_length'] = -23

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('bit_length' in str(exception))

    def test_should_fail_non_integer_bit_length(self):
        self.secret_req['bit_length'] = "23"

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('bit_length' in str(exception))

    def test_should_fail_secret_not_order_schema_provided(self):
        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.secret_req)

        exception = e.exception
        self.assertTrue('secret' in str(exception))

    def test_should_fail_plain_text_provided(self):
        self.secret_req['plain_text'] = '  '

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('plain_text' in str(exception))

    def test_should_fail_already_expired(self):
        self.secret_req['expiration'] = '2004-02-28T19:14:44.180394'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('expiration' in str(exception))

    def test_should_fail_expiration_nonsense(self):
        self.secret_req['expiration'] = 'nonsense'

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('expiration' in str(exception))

    def test_should_fail_all_nulls(self):
        self.secret_req = {'name': None,
                           'algorithm': None,
                           'bit_length': None,
                           'cypher_type': None}
        self.order_req = {'secret': self.secret_req}

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))

    def test_should_fail_all_empties(self):
        self.secret_req = {'name': '',
                           'algorithm': '',
                           'bit_length': '',
                           'cypher_type': ''}
        self.order_req = {'secret': self.secret_req}

        with self.assertRaises(excep.InvalidObject) as e:
            self.validator.validate(self.order_req)

        exception = e.exception
        self.assertTrue('mime_type' in str(exception))


if __name__ == '__main__':
    unittest.main()
