# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.behaviors import secretstores_behaviors
from functionaltests.common import config

CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a
admin_b = CONF.rbac_users.admin_b
observer_b = CONF.rbac_users.observer_b

test_user_data_when_enabled = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 200},
}

test_user_data_admin_ops_when_enabled = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
}

test_user_data_when_not_enabled = {
    'with_admin_a': {'user': admin_a, 'expected_return': 404},
    'with_creator_a': {'user': creator_a, 'expected_return': 404},
    'with_observer_a': {'user': observer_a, 'expected_return': 404},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 404},
}


@utils.parameterized_test_case
class SecretStoresTestCase(base.TestCase):
    """Functional tests exercising ACL Features"""
    def setUp(self):
        super(SecretStoresTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.ss_behaviors = secretstores_behaviors.SecretStoresBehaviors(
            self.client)

    def tearDown(self):
        self.ss_behaviors.cleanup_preferred_secret_store_entities()
        self.secret_behaviors.delete_all_created_secrets()
        super(SecretStoresTestCase, self).tearDown()

    def _validate_secret_store_fields(self, secret_store):
        self.assertIsNotNone(secret_store['name'])
        self.assertIsNotNone(secret_store['secret_store_ref'])
        self.assertIsNotNone(secret_store['secret_store_plugin'])
        self.assertIsNotNone(secret_store['global_default'])
        self.assertIsNotNone(secret_store['created'])
        self.assertIsNotNone(secret_store['updated'])
        self.assertEqual("ACTIVE", secret_store['status'])

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset(test_user_data_when_enabled)
    def test_get_all_secret_stores_multiple_enabled(self, user,
                                                    expected_return):

        resp, json_data = self.ss_behaviors.get_all_secret_stores(
            user_name=user)

        self.assertEqual(expected_return, resp.status_code)
        if expected_return == 200:
            self.assertIsNotNone(json_data.get('secret_stores'))
            stores = json_data['secret_stores']
            for secret_store in stores:
                self._validate_secret_store_fields(secret_store)

    @testcase.skipIf(base.conf_multiple_backends_enabled, 'executed only when '
                     'multiple backends support is NOT enabled in barbican '
                     'server side')
    @utils.parameterized_dataset(test_user_data_when_not_enabled)
    def test_get_all_secret_stores_multiple_disabled(self, user,
                                                     expected_return):

        resp, _ = self.ss_behaviors.get_all_secret_stores(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset(test_user_data_when_enabled)
    def test_get_global_default_multiple_enabled(self, user, expected_return):

        resp, json_data = self.ss_behaviors.get_global_default(user_name=user)

        self.assertEqual(expected_return, resp.status_code)
        if expected_return == 200:
            self._validate_secret_store_fields(json_data)

    @testcase.skipIf(base.conf_multiple_backends_enabled, 'executed only when '
                     'multiple backends support is NOT enabled in barbican '
                     'server side')
    @utils.parameterized_dataset(test_user_data_when_not_enabled)
    def test_get_global_default_multiple_disabled(self, user, expected_return):

        resp, _ = self.ss_behaviors.get_global_default(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset(test_user_data_when_enabled)
    def test_get_project_preferred_multiple_enabled(self, user,
                                                    expected_return):

        resp, json_data = self.ss_behaviors.get_all_secret_stores(
            user_name=admin_a)
        self.assertEqual(200, resp.status_code)

        stores = json_data['secret_stores']

        store = stores[len(stores) - 1]
        secret_store_ref = store['secret_store_ref']
        resp = self.ss_behaviors.set_preferred_secret_store(secret_store_ref,
                                                            user_name=user)

        if resp.status_code == 204:
            resp, json_data = self.ss_behaviors.get_project_preferred_store(
                user_name=user)

            self.assertEqual(expected_return, resp.status_code)
            if expected_return == 200:
                self._validate_secret_store_fields(json_data)
                self.assertEqual(store['secret_store_ref'],
                                 json_data['secret_store_ref'])

    @testcase.skipIf(base.conf_multiple_backends_enabled, 'executed only when '
                     'multiple backends support is NOT enabled in barbican '
                     'server side')
    @utils.parameterized_dataset(test_user_data_when_not_enabled)
    def test_get_project_preferred_multiple_disabled(self, user,
                                                     expected_return):

        resp, _ = self.ss_behaviors.get_project_preferred_store(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset(test_user_data_when_enabled)
    def test_get_a_secret_store_multiple_enabled(self, user, expected_return):
        # read global default secret store via admin user as this is not a
        # global default API check.
        resp, json_data = self.ss_behaviors.get_global_default(
            user_name=admin_a)
        self.assertEqual(200, resp.status_code)

        resp, json_data = self.ss_behaviors.get_a_secret_store(
            json_data['secret_store_ref'], user_name=user)

        self.assertEqual(expected_return, resp.status_code)
        if expected_return == 200:
            self._validate_secret_store_fields(json_data)
            self.assertTrue(json_data['global_default'])

    @testcase.skipIf(base.conf_multiple_backends_enabled, 'executed only when '
                     'multiple backends support is NOT enabled in barbican '
                     'server side')
    @utils.parameterized_dataset(test_user_data_when_not_enabled)
    def test_get_a_secret_store_multiple_disabled(self, user, expected_return):

        resp, _ = self.ss_behaviors.get_project_preferred_store(user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset(test_user_data_admin_ops_when_enabled)
    def test_unset_project_preferred_store_multiple_enabled(self, user,
                                                            expected_return):

        resp, json_data = self.ss_behaviors.get_all_secret_stores(
            user_name=admin_a)
        self.assertEqual(200, resp.status_code)

        stores = json_data['secret_stores']

        store = stores[len(stores) - 1]
        secret_store_ref = store['secret_store_ref']
        resp = self.ss_behaviors.set_preferred_secret_store(secret_store_ref,
                                                            user_name=user)

        if resp.status_code == 204:
            # after setting project preference, get preferred will return 200
            resp, json_data = self.ss_behaviors.get_project_preferred_store(
                user_name=user)
            self.assertEqual(200, resp.status_code)

            # now, remove project preferred secret store
            self.ss_behaviors.unset_preferred_secret_store(
                json_data['secret_store_ref'], user_name=user)
            # get project preferred call should now return 404
            resp, json_data = self.ss_behaviors.get_project_preferred_store(
                user_name=user)
            self.assertEqual(404, resp.status_code)
