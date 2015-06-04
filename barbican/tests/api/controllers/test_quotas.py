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
        self.assertIn('quotas', resp.namespace)

    def test_should_get_specific_project_quotas(self):
        params = {}
        resp = self.app.get(
            '/project-quotas/{0}'.format(self.project_id),
            params)
        self.assertEqual(200, resp.status_int)
        self.assertIn('project_quotas', resp.namespace)

    def test_should_get_project_quotas_list(self):
        params = {}
        resp = self.app.get('/project-quotas', params)
        self.assertEqual(200, resp.status_int)
        self.assertIn('project_quotas', resp.namespace)

    def test_should_post_project_quotas(self):
        request = {'project_quotas': {}}
        resp = self.app.post_json(
            '/project-quotas/{0}'.format(self.project_id), request)
        self.assertEqual(200, resp.status_int)

    def test_should_delete_specific_project_quotas(self):
        params = {}
        resp = self.app.delete(
            '/project-quotas/{0}'.format(self.project_id), params)
        self.assertEqual(204, resp.status_int)

    def test_check_post_quotas_not_allowed(self):
        """POST not allowed operation for /quotas"""
        params = {}
        resp = self.app.post('/quotas/', params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_check_put_project_quotas_not_allowed(self):
        """PUT not allowed operation for /project-quotas/{project-id}"""
        params = {}
        resp = self.app.put(
            '/project-quotas/{0}'.format(self.project_id),
            params, expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_check_post_project_quotas_list_not_allowed(self):
        """POST not allowed operation for /project-quotas"""
        params = {}
        resp = self.app.post('/project-quotas', params, expect_errors=True)
        self.assertEqual(405, resp.status_int)


if __name__ == '__main__':
    unittest.main()
