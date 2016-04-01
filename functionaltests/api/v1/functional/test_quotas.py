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

from testtools import testcase

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
        self.project_id = self.behaviors.get_project_id_from_name(
            CONF.identity.username)

    def tearDown(self):
        self.behaviors.delete_all_created_quotas()
        super(QuotasTestCase, self).tearDown()

    def test_get_quotas_with_defaults(self):
        """Get effective quota information for own project"""

        resp = self.behaviors.get_quotas()

        self.assertEqual(200, resp.status_code)
        self.assertEqual(CONF.quotas.quota_secrets,
                         resp.model.quotas.secrets)
        self.assertEqual(CONF.quotas.quota_orders,
                         resp.model.quotas.orders)
        self.assertEqual(CONF.quotas.quota_containers,
                         resp.model.quotas.containers)
        self.assertEqual(CONF.quotas.quota_consumers,
                         resp.model.quotas.consumers)
        self.assertEqual(CONF.quotas.quota_cas,
                         resp.model.quotas.cas)

    def test_get_project_quotas_by_project_id(self):
        """Get project quota information for specific project"""

        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        resp = self.behaviors.set_project_quotas('44444',
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(204, resp.status_code)

        resp = self.behaviors.get_project_quotas('44444',
                                                 user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(50, resp.model.project_quotas.secrets)
        self.assertEqual(10, resp.model.project_quotas.orders)
        self.assertEqual(20, resp.model.project_quotas.containers)
        self.assertIsNone(resp.model.project_quotas.consumers)
        self.assertIsNone(resp.model.project_quotas.cas)

    def test_get_project_quotas_by_project_id_not_found(self):
        """Get project quota information for specific project"""
        resp = self.behaviors.get_project_quotas('dummy',
                                                 user_name=service_admin)
        self.assertEqual(404, resp.status_code)

    def test_delete_project_quotas(self):
        """Delete project quota information"""
        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        resp = self.behaviors.set_project_quotas('55555',
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(204, resp.status_code)

        resp = self.behaviors.delete_project_quotas('55555',
                                                    user_name=service_admin)
        self.assertEqual(204, resp.status_code)

    def test_delete_project_quotas_not_found(self):
        """Get project quota information"""
        resp = self.behaviors.delete_project_quotas('dummy',
                                                    user_name=service_admin)
        self.assertEqual(404, resp.status_code)


@testcase.attr('no_parallel')
class ProjectQuotasPagingTestCase(base.PagingTestCase):

    def setUp(self):
        super(ProjectQuotasPagingTestCase, self).setUp()
        self.behaviors = quota_behaviors.QuotaBehaviors(self.client)
        resp, project_quotas_list, _, _ =\
            self.behaviors.get_project_quotas_list(user_name=service_admin)
        self.original_project_quota_count = len(project_quotas_list)

    def tearDown(self):
        self.behaviors.delete_all_created_quotas()
        super(ProjectQuotasPagingTestCase, self).tearDown()

    def create_model(self):
        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        return request_model

    def create_resources(self, count=0, model=None):
        for x in range(0, count):
            self.behaviors.set_project_quotas(str(x), model,
                                              user_name=service_admin)

    def get_resources(self, limit=10, offset=0, filter=None):
        return self.behaviors.get_project_quotas_list(
            limit=limit, offset=offset, user_name=service_admin)

    def set_filter_field(self, unique_str, model):
        """ProjectQuotas API does not support filter """
        pass

    def test_get_project_quota_list_none(self):
        """Get list of all project quotas, when there are none"""

        resp, project_quotas_list, _, _ =\
            self.behaviors.get_project_quotas_list(user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.original_project_quota_count,
                         len(project_quotas_list))

    def test_get_project_quota_list_one(self):
        """Get list of all project quotas, when there is one"""

        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        resp = self.behaviors.set_project_quotas('11111',
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(204, resp.status_code)

        resp, project_quotas_list, _, _ =\
            self.behaviors.get_project_quotas_list(user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.original_project_quota_count + 1,
                         len(project_quotas_list))

    def test_get_project_quota_list_two(self):
        """Get list of all project quotas, when there is one"""

        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        resp = self.behaviors.set_project_quotas('22222',
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.behaviors.set_project_quotas('33333',
                                                 request_model,
                                                 user_name=service_admin)
        self.assertEqual(204, resp.status_code)

        resp, project_quotas_list, _, _ =\
            self.behaviors.get_project_quotas_list(user_name=service_admin)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.original_project_quota_count + 2,
                         len(project_quotas_list))
