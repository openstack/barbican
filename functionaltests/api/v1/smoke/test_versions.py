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
from functionaltests.api import base


class VersionDiscoveryTestCase(base.TestCase):

    def test_version_get_as_unauthenticated(self):
        """Covers retrieving version as unauthenticated user."""
        self._do_version_test(use_auth=False)

    def test_version_get_as_authenticated(self):
        """Covers retrieving version as authenticated user."""
        self._do_version_test(use_auth=True)

    def _do_version_test(self, use_auth=False):
        """Get version string with or without authentication.

        :param use_auth: True to use authentication, False otherwise.  Default
        is False
        """
        url_without_version = self.client.get_base_url(include_version=False)
        resp = self.client.get(url_without_version, use_auth=use_auth)
        body = resp.json()

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body.get('v1'), 'current')
        self.assertGreater(len(body.get('build')), 1)
