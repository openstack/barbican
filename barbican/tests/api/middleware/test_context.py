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

import mock
import webob.exc

from barbican.api.middleware import context
from barbican.tests import utils


class WhenTestingBaseContextMiddleware(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingBaseContextMiddleware, self).setUp()

    def test_should_raise_attribute_error(self):
        base = context.BaseContextMiddleware(None)
        self.assertRaises(AttributeError, base.process_response, None)


class WhenTestingContextMiddleware(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingContextMiddleware, self).setUp()

    def test_should_raise_attribute_error(self):

        middle = context.ContextMiddleware(None)
        request = mock.MagicMock()
        request.headers = {
            'X-Service-Catalog': 'force json error'
        }

        exception_result = self.assertRaises(
            webob.exc.HTTPInternalServerError,
            middle._get_authenticated_context,
            request)

        self.assertEqual(
            'Problem processing X-Service-Catalog', exception_result.message)
