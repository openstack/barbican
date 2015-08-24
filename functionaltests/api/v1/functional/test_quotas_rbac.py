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

import uuid

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import quota_behaviors
from functionaltests.api.v1.models import quota_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a
service_admin = CONF.identity.service_admin

test_data_rbac_get_quotas = {
    'with_service_admin': {'user': service_admin, 'admin': service_admin,
                           'expected_return': 200},
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 200},
}


test_data_rbac_get_project_quotas = {
    'with_service_admin': {'user': service_admin, 'admin': service_admin,
                           'expected_return': 200},
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 403},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_set_project_quotas = {
    'with_service_admin': {'user': service_admin, 'admin': service_admin,
                           'expected_return': 204},
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 403},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


test_data_rbac_delete_project_quotas = {
    'with_service_admin': {'user': service_admin, 'admin': service_admin,
                           'expected_return': 204},
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 403},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


def get_set_project_quotas_request():
    return {"project_quotas":
            {"secrets": 50,
             "orders": 10,
             "containers": 20}}


@utils.parameterized_test_case
class RBACQuotasTestCase(base.TestCase):
    """Functional tests exercising RBAC Policies"""
    def setUp(self):
        super(RBACQuotasTestCase, self).setUp()
        self.behaviors = quota_behaviors.QuotaBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_quotas()
        super(RBACQuotasTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_rbac_get_quotas)
    def test_rbac_get_quotas(self, user, admin, expected_return):
        """Test RBAC for get quotas

        Issue a get quotas and verify that that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the get
        :param admin: the admin of the group owning quotas
        :param expected_return: the expected http return code
        """
        resp = self.behaviors.get_quotas(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_get_project_quotas)
    def test_rbac_get_project_quotas(self, user, admin, expected_return):
        """Test RBAC for get project quotas

        Issue a get quotas and verify that that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the get
        :param admin: the admin of the group owning quotas
        :param expected_return: the expected http return code
        """
        resp, _, _, _ = self.behaviors.get_project_quotas_list(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_set_project_quotas)
    def test_rbac_set_project_quotas(self, user, admin, expected_return):
        """Test RBAC for set project quotas

        Issue a set project quotas and verify that that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the set
        :param admin: the admin of the group owning quotas
        :param expected_return: the expected http return code
        """
        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        project_id = str(uuid.uuid4())
        resp = self.behaviors.set_project_quotas(project_id,
                                                 request_model,
                                                 user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_delete_project_quotas)
    def test_rbac_delete_project_quotas(self, user, admin, expected_return):
        """Test RBAC for delete project quotas

        Issue a set project quotas and verify that that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the delete
        :param admin: the admin of the group owning quotas
        :param expected_return: the expected http return code
        """
        request_model = quota_models.ProjectQuotaRequestModel(
            **get_set_project_quotas_request())
        project_id = str(uuid.uuid4())
        resp = self.behaviors.set_project_quotas(project_id,
                                                 request_model,
                                                 user_name=service_admin)
        resp = self.behaviors.delete_project_quotas(project_id,
                                                    user_name=user)
        self.assertEqual(expected_return, resp.status_code)
