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
import json
import testtools

from functionaltests.api import base


class VersionDiscoveryTestCase(base.TestCase):

    @testtools.skipIf(True, 'Skip until blueprint fix-version-api is complete')
    def test_get_root_discovers_v1(self):
        """Covers retrieving version data for Barbican.
        """
        resp, body = self.client.get(' ')
        body = json.loads(body)

        self.assertEqual(resp.status, 200)
        self.assertEqual(body.get('v1'), 'current')
        self.assertGreater(len(body.get('build')), 1)
