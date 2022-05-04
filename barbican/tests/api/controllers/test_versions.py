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
from barbican.common import utils as cmn_utils
from barbican.tests import utils


class WhenTestingVersionsResource(utils.BarbicanAPIBaseTestCase):
    root_controller = controllers.versions.VersionsController()

    def tearDown(self):
        super(WhenTestingVersionsResource, self).tearDown()
        cmn_utils.CONF.clear_override('host_href')

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

    def test_should_return_version_json_v1_0(self):
        # NOTE: this is for clients that do not have the microversion set
        # which should default to the old-pre-microversion behavior
        resp = self.app.get('/')

        versions_response = resp.json['versions']['values']
        v1_info = versions_response[0]

        self.assertIn('v1', v1_info['id'])
        self.assertNotIn('min_version', v1_info)
        self.assertNotIn('max_version', v1_info)
        self.assertEqual(1, len(v1_info['media-types']))
        self.assertEqual('application/json', v1_info['media-types'][0]['base'])

    def test_should_return_version_json_v1_1(self):
        utils.set_version(self.app, '1.1')
        resp = self.app.get('/')

        versions_response = resp.json['versions']
        v1_info = versions_response[0]

        self.assertIn('v1', v1_info['id'])
        self.assertEqual('1.0', v1_info['min_version'])
        self.assertIn('max_version', v1_info)
        self.assertNotIn('media-types', v1_info)

    def test_when_host_href_is_not_set_in_conf_v0(self):
        cmn_utils.CONF.set_override('host_href', '')
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr)
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']['values']

        for v_info in versions_response:
            self.assertNotIn('min_version', v_info)
            self.assertNotIn('max_version', v_info)
            self.assertIn(host_hdr, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])

    def test_when_host_href_is_not_set_in_conf_v1(self):
        cmn_utils.CONF.set_override('host_href', '')
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr, version='1.1')
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']

        for v_info in versions_response:
            self.assertEqual('1.0', v_info['min_version'])
            self.assertIn('max_version', v_info)
            self.assertIn(host_hdr, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])

    def test_when_host_href_is_set_in_conf_v0(self):
        host_href = 'http://myapp.server.com:9311/'
        cmn_utils.CONF.set_override('host_href', host_href)
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr)
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']['values']

        for v_info in versions_response:
            self.assertNotIn('min_version', v_info)
            self.assertNotIn('max_version', v_info)
            self.assertIn(host_href, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])
            self.assertNotIn(host_hdr, v_info['links'][0]['href'])

    def test_when_host_href_is_set_in_conf_v1(self):
        host_href = 'http://myapp.server.com:9311/'
        cmn_utils.CONF.set_override('host_href', host_href)
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr, version='1.1')
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']

        for v_info in versions_response:
            self.assertEqual('1.0', v_info['min_version'])
            self.assertIn('max_version', v_info)
            self.assertIn(host_href, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])
            self.assertNotIn(host_hdr, v_info['links'][0]['href'])

    def test_when_host_href_is_general_v0(self):
        host_href = 'http://myapp.server.com/key-manager'
        cmn_utils.CONF.set_override('host_href', host_href)
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr)
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']['values']

        for v_info in versions_response:
            self.assertNotIn('min_version', v_info)
            self.assertNotIn('max_version', v_info)
            self.assertIn(host_href, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])
            self.assertNotIn(host_hdr, v_info['links'][0]['href'])

    def test_when_host_href_is_general_v1(self):
        host_href = 'http://myapp.server.com/key-manager'
        cmn_utils.CONF.set_override('host_href', host_href)
        host_hdr = 'http://myproxy.server.com:9311'
        utils.mock_pecan_request(self, host=host_hdr, version='1.1')
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']

        for v_info in versions_response:
            self.assertEqual('1.0', v_info['min_version'])
            self.assertIn('max_version', v_info)
            self.assertIn(host_href, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])
            self.assertNotIn(host_hdr, v_info['links'][0]['href'])

    def test_when_host_href_is_not_set_with_general_request_url_v0(self):
        cmn_utils.CONF.set_override('host_href', '')
        host_hdr = 'http://myproxy.server.com/key-manager'
        utils.mock_pecan_request(self, host=host_hdr)
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']['values']

        for v_info in versions_response:
            self.assertNotIn('min_version', v_info)
            self.assertNotIn('max_version', v_info)
            self.assertIn(host_hdr, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])

    def test_when_host_href_is_not_set_with_general_request_url_v1(self):
        cmn_utils.CONF.set_override('host_href', '')
        host_hdr = 'http://myproxy.server.com/key-manager'
        utils.mock_pecan_request(self, host=host_hdr, version='1.1')
        dummy_root = 'http://mylocalhost:9999'
        resp = self.app.get(dummy_root)

        versions_response = resp.json['versions']

        for v_info in versions_response:
            self.assertEqual('1.0', v_info['min_version'])
            self.assertIn('max_version', v_info)
            self.assertIn(host_hdr, v_info['links'][0]['href'])
            self.assertNotIn(dummy_root, v_info['links'][0]['href'])


class WhenTestingV1Resource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingV1Resource, self).setUp()
        # For V1Controller, '/' URI maps to /v1 resource path
        self.root_controller = controllers.versions.V1Controller

    def test_get_for_json_accept_header(self):
        headers = {'Accept': 'application/json'}
        resp = self.app.get('/', headers=headers)  # / refers to /v1 path
        self.assertEqual(200, resp.status_int)

    def test_get_for_json_home_accept_header(self):
        headers = {'Accept': 'application/json-home'}
        resp = self.app.get('/', headers=headers)  # / refers to /v1 path
        self.assertEqual(200, resp.status_int)

    def test_get_response_should_return_version_json_v1_0(self):
        resp = self.app.get('/')  # / refers to /v1 path
        self.assertEqual(200, resp.status_int)

        v1_info = resp.json['version']

        # NOTE(jaosorior): I used assertIn instead of assertEqual because we
        # might start using decimal numbers in the future. So when that happens
        # this test will still be valid.
        self.assertIn('v1', v1_info['id'])
        self.assertNotIn('max_version', v1_info)
        self.assertNotIn('min_version', v1_info)
        self.assertEqual(1, len(v1_info['media-types']))
        self.assertEqual('application/json', v1_info['media-types'][0]['base'])

    def test_get_response_should_return_version_json_v1_1(self):
        utils.set_version(self.app, '1.1')
        resp = self.app.get('/')  # / refers to /v1 path
        self.assertEqual(200, resp.status_int)

        v1_info = resp.json['version']

        # NOTE(jaosorior): I used assertIn instead of assertEqual because we
        # might start using decimal numbers in the future. So when that happens
        # this test will still be valid.
        self.assertIn('v1', v1_info['id'])
        self.assertIn('max_version', v1_info)
        self.assertIn('min_version', v1_info)
        self.assertNotIn('media-types', v1_info)
