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
from barbican.api import controllers
from barbican.tests import utils


class WhenTestingVersionResource(utils.BarbicanAPIBaseTestCase):
    root_controller = controllers.versions.VersionController()

    def test_should_return_200_on_get(self):
        resp = self.app.get('/')
        self.assertEqual(200, resp.status_int)

    def test_should_return_version_json(self):
        resp = self.app.get('/')

        self.assertTrue('v1' in resp.json)
        self.assertEqual(resp.json.get('v1'), 'current')
