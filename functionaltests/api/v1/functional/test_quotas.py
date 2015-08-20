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

from functionaltests.api import base
from functionaltests.api.v1.behaviors import quota_behaviors
from functionaltests.api.v1.models import quota_models
from functionaltests.common import config


CONF = config.get_config()
service_admin = CONF.identity.service_admin


def get_set_project_quotas_request():
    return {"project_quotas":
            {"secrets": 50,
             "orders": 10,
             "containers": 20}}


class QuotasTestCase(base.TestCase):

    def setUp(self):
        super(QuotasTestCase, self).setUp()
        self.behaviors = quota_behaviors.QuotaBehaviors(self.client)
        self.project_id = self.behaviors.get_project_id_from_name('admin')

    def tearDown(self):
        super(QuotasTestCase, self).tearDown()

    def test_get_quotas(self):
        """Get quota information"""

        resp = self.behaviors.get_quotas()

        self.assertEqual(200, resp.status_code)
        self.assertEqual(500, resp.model.quotas['secrets'])
        self.assertEqual(100, resp.model.quotas['transport_keys'])
        self.assertEqual(100, resp.model.quotas['orders'])
        self.assertEqual(-1, resp.model.quotas['containers'])
        self.assertEqual(100, resp.model.quotas['consumers'])

    def test_get_project_quota_list(self):
        """Get list of all project quotas"""

        resp, project_quotas_list = self.behaviors.get_project_quotas_list(
            user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        for project_quotas in project_quotas_list:
            self.assertEqual(500, project_quotas.project_quotas['secrets'])
            self.assertEqual(100,
                             project_quotas.project_quotas['transport_keys'])
            self.assertEqual(100, project_quotas.project_quotas['orders'])
            self.assertEqual(-1, project_quotas.project_quotas['containers'])
            self.assertEqual(100, project_quotas.project_quotas['consumers'])

    def test_get_one_project_quotas(self):
        """Get project quota information for specific project"""

        resp = self.behaviors.get_project_quotas(self.project_id,
                                                 user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(500, resp.model.project_quotas['secrets'])
        self.assertEqual(100, resp.model.project_quotas['transport_keys'])
        self.assertEqual(100, resp.model.project_quotas['orders'])
        self.assertEqual(-1, resp.model.project_quotas['containers'])
        self.assertEqual(100, resp.model.project_quotas['consumers'])

    def test_set_project_quotas(self):
        """Set project quota information"""

        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        resp = self.behaviors.set_project_quotas(self.project_id,
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(200, resp.status_code)

    def test_delete_project_quotas(self):
        """Delete project quota information"""

        resp = self.behaviors.delete_project_quotas(self.project_id,
                                                    user_name=service_admin)
        self.assertEqual(204, resp.status_code)
