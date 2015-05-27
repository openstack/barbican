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
import base64

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a


test_data_rbac_store_secret = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 201},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 201},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_update_secret = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 204},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 204},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_get_secret_metadata = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 200},
}

test_data_rbac_get_decrypted_secret = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_get_list_of_secrets = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_delete_secret = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 204},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
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
        "payload": get_default_payload(),
        "payload_content_type": get_default_payload_content_type(),
        "payload_content_encoding": get_default_payload_content_encoding(),
    }


def get_default_two_phase_secret_data():
    return {
        "name": "AES key",
        "expiration": "2050-02-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
    }


def get_default_two_phase_payload_data():
    return {
        "payload": get_default_payload(),
        "payload_content_type": get_default_payload_content_type(),
        "payload_content_encoding": get_default_payload_content_encoding(),
    }


def get_default_payload():
    return 'Z0Y2K2xMb0Yzb2hBOWFQUnB0KzZiUT09'


def get_default_payload_content_encoding():
    return 'base64'


def get_default_payload_content_type():
    return 'application/octet-stream'


def get_container_req(secret_ref):
    return {"name": "testcontainer",
            "type": "generic",
            "secret_refs": [{'name': 'secret1', 'secret_ref': secret_ref}]}


@utils.parameterized_test_case
class RBACSecretsTestCase(base.TestCase):
    """Functional tests exercising RBAC Policies"""
    def setUp(self):
        super(RBACSecretsTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(RBACSecretsTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_rbac_store_secret)
    def test_rbac_store_secret(self, user, admin, expected_return):
        """Test RBAC for secret store

        Issue a secret creation and verify that that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the store
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        test_model = secret_models.SecretModel(**get_default_secret_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=user, admin=admin)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 201, secret_ref is not None)

    @utils.parameterized_dataset(test_data_rbac_update_secret)
    def test_rbac_update_secret(self, user, admin, expected_return):
        """Test RBAC for secret update

        Issue a secret update and verify that that the correct
        http return code comes back for the specified user.

        The initial secret will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the secret
        store to fail since we are only testing secret update here.

        :param user: the user who will attempt to do the update
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """

        secret_ref = self._create_initial_secret(
            admin=admin, secret_data=get_default_two_phase_secret_data())

        resp = self.secret_behaviors.update_secret_payload(
            secret_ref, user_name=user,
            **get_default_two_phase_payload_data())
        self.assertEqual(expected_return, resp.status_code)

    @utils.parameterized_dataset(test_data_rbac_get_secret_metadata)
    def test_rbac_get_secret_metadata(self, user, admin, expected_return):
        """Test RBAC for secret get metadata

        Issue a secret get metadata and verify that that the correct
        http return code comes back for the specified user.

        The initial secret will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the secret
        store to fail since we are only testing secret get metadata here.

        :param user: the user who will attempt to do the get metadata
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        secret_ref = self._create_initial_secret(admin=admin)

        resp = self.secret_behaviors.get_secret_metadata(
            secret_ref, user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 200, resp.content is not None)

    @utils.parameterized_dataset(test_data_rbac_get_decrypted_secret)
    def test_rbac_get_decrypted_secret(self, user, admin, expected_return):
        """Test RBAC for secret get decrypted secret

        Issue a secret get decrypted data and verify that that the correct
        http return code comes back for the specified user.

        The initial secret will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the secret
        store to fail since we are only testing get decrypted secret here.

        :param user: the user who will attempt to get the decrypted secret
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        secret_ref = self._create_initial_secret(admin=admin)

        resp = self.secret_behaviors.get_secret(
            secret_ref, payload_content_type='application/octet-stream',
            user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 200,
                         resp.content == base64.b64decode(
                             get_default_payload()))

    @utils.parameterized_dataset(test_data_rbac_get_list_of_secrets)
    def test_rbac_get_list_of_secrets(self, user, admin, expected_return):
        """Test RBAC for get secret list

        Issue a get secret list and verify that that the correct
        http return code comes back for the specified user.

        Some initial secrets will be stored with the admin user to ensure
        that they get created successfully.  We don't want the secret
        stores to fail since we are only testing get secret list.

        :param user: the user who will attempt to get the list of secrets
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        for i in range(3):
            secret_ref = self._create_initial_secret(admin=admin)

        self.assertIsNotNone(secret_ref)
        resp, secrets, next, prev = self.secret_behaviors.get_secrets(
            limit=10, offset=0, user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertIsNotNone(secrets)

    @utils.parameterized_dataset(test_data_rbac_delete_secret)
    def test_rbac_delete_secret(self, user, admin, expected_return):
        """Test RBAC for secret delete

        Issue a secret delete and verify that that the correct
        http return code comes back for the specified user.

        The initial secret will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the secret
        store to fail since we are only testing secret delete here.

        :param user: the user who will attempt to do the delete
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        secret_ref = self._create_initial_secret(admin=admin)

        resp = self.secret_behaviors.delete_secret(
            secret_ref, user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    def _create_initial_secret(self, admin=admin_a,
                               secret_data=get_default_secret_data()):
        """Utility function to create a secret

        Some tests require a secret to exist before they test certain things,
        so this function can be used to do that setup.

        :param admin: the admin user who will create store the secret
        :param secret_data: the data for the secret
        :return: href to the newly stored secret
        """
        test_model = secret_models.SecretModel(**secret_data)
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=admin, admin=admin)
        self.assertEqual(201, resp.status_code)
        return secret_ref
