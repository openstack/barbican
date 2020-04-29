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

"""
This test module tests the barbican.api.__init__.py module functionality.
"""
from unittest import mock

from oslo_serialization import jsonutils as json

from barbican import api
from barbican.common import exception
from barbican.plugin.interface import secret_store
from barbican.tests import utils


class WhenInvokingLoadBodyFunction(utils.BaseTestCase):
    """Tests the load_body function."""

    @mock.patch('pecan.abort')
    def test_should_abort_with_read_error(self, mock_pecan_abort):
        mock_pecan_abort.side_effect = ValueError('Abort!')

        req = mock.MagicMock()
        req.body_file = mock.MagicMock()
        req.body_file.read.side_effect = IOError('Dummy IOError')

        exception = self.assertRaises(
            ValueError, api.load_body, req)

        self.assertEqual('Abort!', str(exception))

    @mock.patch('pecan.abort')
    def test_should_abort_with_validation_unsupported_field(
            self, mock_pecan_abort):
        mock_pecan_abort.side_effect = ValueError('Abort!')

        body = json.dumps({'key1': 'value1'})

        req = mock.MagicMock()
        req.body_file = mock.MagicMock()
        req.body_file.read.return_value = body

        validator = mock.MagicMock()
        validator.validate.side_effect = exception.UnsupportedField('Field')

        exception_result = self.assertRaises(
            ValueError, api.load_body, req, validator=validator)

        self.assertEqual('Abort!', str(exception_result))
        validator.validate.assert_called_once_with(json.loads(body))


class WhenInvokingGenerateSafeExceptionMessageFunction(utils.BaseTestCase):
    """Tests the generate_safe_exception_message function."""

    def setUp(self):
        super(WhenInvokingGenerateSafeExceptionMessageFunction, self).setUp()

    def test_handle_secret_content_type_not_supported_exception(self):
        operation = 'operation'
        content_type = 'application/octet-stream'
        test_exception = secret_store.SecretContentTypeNotSupportedException(
            content_type)

        status, message = api.generate_safe_exception_message(
            operation, test_exception)

        self.assertEqual(400, status)
        self.assertEqual("operation issue seen - content-type of "
                         "'application/octet-stream' not "
                         "supported.", message)

    def test_handle_secret_content_encoding_not_supported_exception(self):
        operation = 'operation'
        content_encoding = 'application/octet-stream'
        test_excep = secret_store.SecretContentEncodingNotSupportedException(
            content_encoding)

        status, message = api.generate_safe_exception_message(
            operation, test_excep)

        self.assertEqual(400, status)
        self.assertEqual("operation issue seen - content-encoding of "
                         "'application/octet-stream' not "
                         "supported.", message)
