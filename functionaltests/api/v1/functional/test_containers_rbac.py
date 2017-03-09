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
from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
creator_a_2 = CONF.rbac_users.creator_a_2
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a


test_data_rbac_store_container = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 201},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 201},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


test_data_rbac_update_container = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 405},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 405},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 405},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 405},
}


test_data_rbac_delete_container = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 204},
    'with_creator_a': {'user': creator_a, 'admin': creator_a,
                       'expected_return': 204},
    'with_creator_a_2': {'user': creator_a_2, 'admin': creator_a,
                         'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


test_data_rbac_get_container = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 200},
}


test_data_rbac_get_list_of_containers = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


def get_default_secret_data():
    return {
        "name": "AES key",
        "expiration": "2050-02-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload": 'Z0Y2K2xMb0Yzb2hBOWFQUnB0KzZiUT09',
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64",
    }


def get_container_req(secret_ref):
    return {"name": "testcontainer",
            "type": "generic",
            "secret_refs": [{'name': 'secret1', 'secret_ref': secret_ref}]}


@utils.parameterized_test_case
class RBACContainersTestCase(base.TestCase):
    """Functional tests exercising RBAC Policies"""
    def setUp(self):
        super(RBACContainersTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        super(RBACContainersTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_rbac_store_container)
    def test_rbac_store_container(self, user, admin, expected_return):
        """Test RBAC for container store

        Issue a container store and verify that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the store
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """

        test_model = secret_models.SecretModel(
            **get_default_secret_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=admin, admin=admin)
        self.assertEqual(201, resp.status_code)

        test_model = container_models.ContainerModel(
            **get_container_req(secret_ref))
        resp, container_ref = self.container_behaviors.create_container(
            test_model, user_name=user, admin=admin)
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_update_container)
    def test_rbac_update_container(self, user, admin, expected_return):
        """Test RBAC for container update

        Issue a container update and verify that the correct
        http return code comes back for the specified user.

        The initial container will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the container
        store to fail since we are only testing container update here.

        :param user: the user who will attempt to do the update
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """

        container_ref = self._create_initial_container(admin=admin)

        resp = self.container_behaviors.update_container(container_ref,
                                                         user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_get_container)
    def test_rbac_get_container(self, user, admin, expected_return):
        """Test RBAC for container get

        Issue a container get and verify that the correct
        http return code comes back for the specified user.

        The initial container will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the container
        store to fail since we are only testing container get here.

        :param user: the user who will attempt to do the get metadata
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        container_href = self._create_initial_container(admin=admin)

        resp = self.container_behaviors.get_container(
            container_href, user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 200, resp.content is not None)

    @utils.parameterized_dataset(test_data_rbac_delete_container)
    def test_rbac_delete_container(self, user, admin, expected_return):
        """Test RBAC for container delete

        Issue a container delete and verify that the correct
        http return code comes back for the specified user.

        The initial container will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the container
        store to fail since we are only testing container delete here.

        :param user: the user who will attempt to do the delete
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        container_href = self._create_initial_container(admin=admin)

        resp = self.container_behaviors.delete_container(
            container_href, user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    def _create_initial_container(self, admin=admin_a):
        """Utility function to create a container with a contained secret

        Some tests require a container to exist before they test certain
        things, so this function can be used to do that setup.  First a secret
        will be created, then a container will be created which contains
        that secret.

        :param admin: the admin user who will create store the container
        :param secret_data: the data for the container
        :return: href to the newly stored container
        """
        test_model = secret_models.SecretModel(**get_default_secret_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=admin, admin=admin)
        self.assertEqual(201, resp.status_code)

        test_model = container_models.ContainerModel(
            **get_container_req(secret_ref))
        resp, container_ref = self.container_behaviors.create_container(
            test_model, user_name=admin, admin=admin)
        self.assertEqual(201, resp.status_code)
        return container_ref
