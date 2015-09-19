# Copyright (c) 2015 Rackspace, Inc.
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
import mock
import oslotest.base as oslotest

from barbican.api.middleware import context


class TestUnauthenticatedContextMiddleware(oslotest.BaseTestCase):

    def setUp(self):
        super(TestUnauthenticatedContextMiddleware, self).setUp()
        self.app = mock.MagicMock()
        self.middleware = context.UnauthenticatedContextMiddleware(self.app)

    def test_role_defaults_to_admin(self):
        request = mock.MagicMock()
        request.headers = {'X-Project-Id': 'trace'}
        request.environ = {}

        with mock.patch('barbican.context.RequestContext') as rc:
            self.middleware.process_request(request)
            rc.assert_called_with(
                project='trace',
                is_admin=True,
                user=None,
                roles=['admin'],
                request_id=request.request_id,
                project_domain=None,
                domain=None,
                user_domain=None
            )

    def test_role_used_from_header(self):
        request = mock.MagicMock()
        request.headers = {'X-Project-Id': 'trace', 'X-Roles': 'something'}
        request.environ = {}

        with mock.patch('barbican.context.RequestContext') as rc:
            self.middleware.process_request(request)
            rc.assert_called_with(
                project='trace',
                is_admin=False,
                user=None,
                roles=['something'],
                request_id=request.request_id,
                project_domain=None,
                domain=None,
                user_domain=None
            )
