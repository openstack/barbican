# Copyright (c) 2015 Cisco Systems
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

from barbican.tests import utils


class WhenTestingQuotas(utils.BarbicanAPIBaseTestCase):

    def test_should_get_quotas(self):
        params = {}
        resp = self.app.get('/quotas', params)
        self.assertEqual(200, resp.status_int)
        quotas_list = resp.json.get('quotas')
        self.assertEqual({'consumers': -1, 'containers': -1, 'orders': -1,
                          'secrets': -1, 'cas': -1},
                         quotas_list)

    def test_should_get_specific_project_quotas(self):
        params = {}
        self.create_a_project_quotas()
        resp = self.app.get(
            '/project-quotas/{0}'.format(self.get_test_project_id()),
            params)
        self.assertEqual(200, resp.status_int)
        project_quotas = resp.json.get('project_quotas')
        self.assertEqual({'consumers': 105, 'containers': 103, 'orders': 102,
                          'secrets': 101, 'cas': 106},
                         project_quotas)

    def test_should_return_not_found_get_specific_project_quotas(self):
        params = {}
        resp = self.app.get(
            '/project-quotas/{0}'.format(self.get_test_project_id()),
            params, expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_project_quotas_list(self):
        self.create_project_quotas()
        params = {}
        resp = self.app.get('/project-quotas', params)
        self.assertEqual(200, resp.status_int)
        project_quotas_list = resp.json.get('project_quotas')
        self.assertEqual(3, len(project_quotas_list))
        self.assertIn('total', resp.json)

    def test_should_get_empty_project_quotas_list(self):
        params = {}
        resp = self.app.get('/project-quotas', params)
        self.assertEqual(200, resp.status_int)
        project_quotas_list = resp.json.get('project_quotas')
        self.assertEqual([], project_quotas_list)
        self.assertIn('total', resp.json)

    def test_pagination_attributes(self):
        for index in range(11):
            self.create_a_project_quotas(index)

        params = {'limit': '2', 'offset': '2'}
        resp = self.app.get('/project-quotas', params)

        self.assertEqual(200, resp.status_int)
        self.assertIn('previous', resp.json)
        self.assertIn('next', resp.json)

        previous_ref = resp.json.get('previous')
        next_ref = resp.json.get('next')

        self.assertIn('offset=0', previous_ref)
        self.assertIn('offset=4', next_ref)

    def test_should_put_project_quotas(self):
        request = {'project_quotas': {}}
        resp = self.app.put_json(
            '/project-quotas/{0}'.format(self.project_id), request)
        self.assertEqual(204, resp.status_int)

    def test_should_return_bad_value_put_project_quotas(self):
        request = '{"project_quotas": {"secrets": "foo"}}'
        resp = self.app.put(
            '/project-quotas/{0}'.format(self.project_id),
            request,
            headers={'Content-Type': 'application/json'},
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_should_return_bad_data_put_project_quotas(self):
        """PUT not allowed operation for /project-quotas/{project-id}"""
        params = {'bad data'}
        resp = self.app.put(
            '/project-quotas/{0}'.format(self.project_id),
            params, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_should_return_no_payload_for_put_project_quotas(self):
        """PUT not allowed operation for /project-quotas/{project-id}"""
        params = {}
        resp = self.app.put(
            '/project-quotas/{0}'.format(self.project_id),
            params, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_should_delete_specific_project_quotas(self):
        params = {}
        self.create_a_project_quotas()
        resp = self.app.delete(
            '/project-quotas/{0}'.format(self.get_test_project_id()),
            params)
        self.assertEqual(204, resp.status_int)

    def test_should_return_not_found_delete_specific_project_quotas(self):
        params = {}
        resp = self.app.delete(
            '/project-quotas/{0}'.format('dummy'),
            params, expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_check_put_quotas_not_allowed(self):
        """PuT not allowed operation for /quotas"""
        params = {}
        resp = self.app.put('/quotas/', params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_check_put_project_quotas_list_not_allowed(self):
        """PUT not allowed operation for /project-quotas"""
        params = {}
        resp = self.app.put('/project-quotas', params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_check_post_project_quotas_not_allowed(self):
        """POST not allowed operation for /project-quotas/{project-id}"""
        params = {}
        resp = self.app.post(
            '/project-quotas/{0}'.format(self.project_id),
            params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_check_post_project_quotas_list_not_allowed(self):
        """POST not allowed operation for /project-quotas"""
        params = {}
        resp = self.app.post('/project-quotas', params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    # ----------------------- Helper Functions ---------------------------
    def get_test_project_id(self, index=1):
        return 'project' + str(index)

    def create_a_project_quotas(self, index=1):
        project_id = self.get_test_project_id(index)
        parsed_project_quotas = {
            'secrets': index * 100 + 1,
            'orders': index * 100 + 2,
            'containers': index * 100 + 3,
            'consumers': index * 100 + 5,
            'cas': index * 100 + 6}
        request = {'project_quotas': parsed_project_quotas}
        resp = self.app.put_json(
            '/project-quotas/{0}'.format(project_id), request)
        self.assertEqual(204, resp.status_int)

    def create_project_quotas(self):
        for index in [1, 2, 3]:
            self.create_a_project_quotas(index)


if __name__ == '__main__':
    unittest.main()
