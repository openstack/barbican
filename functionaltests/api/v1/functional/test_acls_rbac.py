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
from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import acl_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import acl_models
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a
admin_b = CONF.rbac_users.admin_b
observer_b = CONF.rbac_users.observer_b


def get_acl_default():
    return {'read': {'project-access': True}}


def get_acl_one():
    return {'read': {'users': ['reader1'], 'project-access': False}}


def get_acl_two():
    return {'read': {'users': ['reader2'], 'project-access': False}}


test_data_set_secret_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_get_secret_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_update_secret_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_delete_secret_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_set_container_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_get_container_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_update_container_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_delete_container_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}


@utils.parameterized_test_case
class RBACAclsTestCase(base.TestCase):
    """Functional tests exercising RBAC Policies for ACL Operations"""
    def setUp(self):
        super(RBACAclsTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.acl_behaviors = acl_behaviors.AclBehaviors(self.client)

    def tearDown(self):
        self.acl_behaviors.delete_all_created_acls()
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        super(RBACAclsTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_set_secret_acl)
    def test_set_secret_acl(self, user, expected_return):
        secret_ref = self.store_secret()
        status = self.set_secret_acl(secret_ref, get_acl_one(),
                                     user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_get_secret_acl)
    def test_get_secret_acl(self, user, expected_return):
        secret_ref = self.store_secret()
        status = self.set_secret_acl(secret_ref, get_acl_one())
        self.assertEqual(200, status)
        resp = self.acl_behaviors.get_acl(secret_ref + '/acl', user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        if expected_return == 200:
            self.assertIn('reader1', resp.model.read['users'])
        else:
            self.assertIsNone(resp.model)

    @utils.parameterized_dataset(test_data_update_secret_acl)
    def test_update_secret_acl(self, user, expected_return):
        secret_ref = self.store_secret()
        status = self.set_secret_acl(secret_ref, get_acl_one())
        self.assertEqual(200, status)
        status, model = self.update_secret_acl(secret_ref,
                                               get_acl_two(),
                                               user_name=user)
        self.assertEqual(expected_return, status)
        get_resp = self.acl_behaviors.get_acl(secret_ref + '/acl',
                                              user_name=admin_a)
        if expected_return == 200:
            self.assertIsNotNone(model.acl_ref)
            # verify update happened
            self.assertIn('reader2', get_resp.model.read['users'])
        else:
            self.assertIsNone(model)
            # verify no update happened
            self.assertIn('reader1', get_resp.model.read['users'])

    @utils.parameterized_dataset(test_data_delete_secret_acl)
    def test_delete_secret_acl(self, user, expected_return):
        secret_ref = self.store_secret()
        status = self.set_secret_acl(secret_ref, get_acl_one())
        self.assertEqual(200, status)
        resp = self.acl_behaviors.delete_acl(secret_ref + '/acl',
                                             user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        get_resp = self.acl_behaviors.get_acl(secret_ref + '/acl',
                                              user_name=admin_a)
        if expected_return == 200:
            # verify delete happened (return to default ACL)
            self.assertTrue(get_resp.model.read['project-access'])
        else:
            # verify no delete happened
            self.assertIn('reader1', get_resp.model.read['users'])

    @utils.parameterized_dataset(test_data_set_container_acl)
    def test_set_container_acl(self, user, expected_return):
        container_ref = self.store_container()
        status = self.set_container_acl(container_ref, get_acl_one(),
                                        user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_get_container_acl)
    def test_get_container_acl(self, user, expected_return):
        container_ref = self.store_container()
        status = self.set_container_acl(container_ref, get_acl_one())
        self.assertEqual(200, status)
        resp = self.acl_behaviors.get_acl(container_ref + '/acl',
                                          user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        if expected_return == 200:
            self.assertIn('reader1', resp.model.read['users'])
        else:
            self.assertIsNone(resp.model)

    @utils.parameterized_dataset(test_data_update_container_acl)
    def test_update_container_acl(self, user, expected_return):
        container_ref = self.store_container()
        status = self.set_container_acl(container_ref, get_acl_one())
        self.assertEqual(200, status)
        status, model = self.update_container_acl(container_ref,
                                                  get_acl_two(),
                                                  user_name=user)
        self.assertEqual(expected_return, status)
        get_resp = self.acl_behaviors.get_acl(container_ref + '/acl',
                                              user_name=admin_a)
        if expected_return == 200:
            self.assertIsNotNone(model.acl_ref)
            # verify update happened
            self.assertIn('reader2', get_resp.model.read['users'])
        else:
            self.assertIsNone(model)
            # verify no update happened
            self.assertIn('reader1', get_resp.model.read['users'])

    @utils.parameterized_dataset(test_data_delete_container_acl)
    def test_delete_container_acl(self, user, expected_return):
        container_ref = self.store_container()
        status = self.set_container_acl(container_ref, get_acl_one())
        self.assertEqual(200, status)
        resp = self.acl_behaviors.delete_acl(container_ref + '/acl',
                                             user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        get_resp = self.acl_behaviors.get_acl(container_ref + '/acl',
                                              user_name=admin_a)
        if expected_return == 200:
            # verify delete happened (return to default ACL)
            self.assertTrue(get_resp.model.read['project-access'])
        else:
            # verify no delete happened
            self.assertIn('reader1', get_resp.model.read['users'])

# ----------------------- Helper Functions ---------------------------

    def store_secret(self, user_name=creator_a, admin=admin_a):
        test_model = secret_models.SecretModel(
            **get_default_secret_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=user_name, admin=admin)
        self.assertEqual(201, resp.status_code)
        return secret_ref

    def set_secret_acl(self, secret_ref, acl, user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.create_acl(
            secret_ref, test_model, user_name=user_name)
        return resp.status_code

    def update_secret_acl(self, secret_ref, acl, user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.update_acl(
            secret_ref + '/acl', test_model, user_name=user_name)
        return resp.status_code, resp.model

    def store_container(self, user_name=creator_a, admin=admin_a):
        secret_ref = self.store_secret(user_name=user_name, admin=admin)

        test_model = container_models.ContainerModel(
            **get_container_req(secret_ref))
        resp, container_ref = self.container_behaviors.create_container(
            test_model, user_name=user_name, admin=admin)
        self.assertEqual(201, resp.status_code)
        return container_ref

    def set_container_acl(self, container_ref, acl, user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.create_acl(
            container_ref, test_model, user_name=user_name)
        return resp.status_code

    def update_container_acl(self, container_ref, acl, user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.update_acl(
            container_ref + '/acl', test_model, user_name=user_name)
        return resp.status_code, resp.model

# ----------------------- Support Functions ---------------------------


def get_default_secret_data():
    return {
        "name": "AES key",
        "expiration": "2050-02-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload": get_default_payload(),
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64",
    }


def get_default_payload():
    return 'Z0Y2K2xMb0Yzb2hBOWFQUnB0KzZiUT09'


def get_container_req(secret_ref):
    return {"name": "testcontainer",
            "type": "generic",
            "secret_refs": [{'name': 'secret1', 'secret_ref': secret_ref}]}
