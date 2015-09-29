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


class WhenTestingVersionsResource(utils.BarbicanAPIBaseTestCase):
    root_controller = controllers.versions.VersionsController()

    def test_should_return_multiple_choices_on_get(self):
        resp = self.app.get('/')
        self.assertEqual(300, resp.status_int)

    def test_should_return_multiple_choices_on_get_if_json_accept_header(self):
        headers = {'Accept': 'application/json'}
        resp = self.app.get('/', headers=headers)
        self.assertEqual(300, resp.status_int)

    def test_should_redirect_if_json_home_accept_header_present(self):
        headers = {'Accept': 'application/json-home'}
        resp = self.app.get('/', headers=headers)
        self.assertEqual(302, resp.status_int)

    def test_should_return_version_json(self):
        resp = self.app.get('/')

        versions_response = resp.json['versions']['values']
        v1_info = versions_response[0]

        # NOTE(jaosorior): I used assertIn instead of assertEqual because we
        # might start using decimal numbers in the future. So when that happens
        # this test will still be valid.
        self.assertIn('v1', v1_info['id'])
        self.assertEqual(1, len(v1_info['media-types']))
        self.assertEqual('application/json', v1_info['media-types'][0]['base'])
