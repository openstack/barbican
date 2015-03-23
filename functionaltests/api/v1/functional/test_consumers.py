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
import copy

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import consumer_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import consumer_model
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models

create_secret_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

default_consumer_data = {
    "name": "consumername",
    "URL": "consumerURL"
}

create_container_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        }
    ]
}

dummy_project_id = 'dummy123'


@utils.parameterized_test_case
class ConsumersUnauthedTestCase(base.TestCase):
    default_data = default_consumer_data

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def setUp(self):
        super(ConsumersUnauthedTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client
        )
        self.consumer_behaviors = consumer_behaviors.ConsumerBehaviors(
            self.client
        )

        self.consumer_data = copy.deepcopy(self.default_data)

        # Set up two secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()

        # Create a container with our secrets
        create_container_data['secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_data['secret_refs'][1]['secret_ref'] = secret_ref_2
        container_model = container_models.ContainerModel(
            **create_container_data
        )

        resp, container_ref = self.container_behaviors.create_container(
            container_model
        )
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(container_ref)

        self.container_ref = container_ref

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(ConsumersUnauthedTestCase, self).tearDown()

    @testcase.attr('negative', 'security')
    def test_consumer_create_unauthed_no_proj_id(self):
        """Attempt to create a consumer without a token or project id

        Should return 401
        """

        model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_dat = self.consumer_behaviors.create_consumer(
            model, self.container_ref, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_get_list_unauthed_no_proj_id(self):
        """Attempt to get the list of consumers w/o a token or project id

        Should return 401
        """

        resp, consumers, next_ref, prev_ref = (
            self.consumer_behaviors.get_consumers(
                self.container_ref, use_auth=False
            )
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_delete_unauthed_no_proj_id(self):
        """Attempt to delete a consumer without a token or project id

        Should return 401
        """

        resp, consumer_dat = self.consumer_behaviors.delete_consumer(
            None, self.container_ref, use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_create_unauthed_with_proj_id(self):
        """Attempt to create a consumer with a project id, but no token

        Should return 401
        """

        model = consumer_model.ConsumerModel(**self.consumer_data)
        headers = {'X-Project-Id': dummy_project_id}
        resp, consumer_dat = self.consumer_behaviors.create_consumer(
            model, self.container_ref, extra_headers=headers, use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_get_list_unauthed_with_proj_id(self):
        """Attempt to get the list of consumers with a project id but no token

        Should return 401
        """

        headers = {'X-Project-Id': dummy_project_id}
        resp, consumers, next_ref, prev_ref = (
            self.consumer_behaviors.get_consumers(
                self.container_ref, extra_headers=headers, use_auth=False
            )
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_delete_unauthed_with_proj_id(self):
        """Attempt to delete a consumer with a project id, but no token

        Should return 401
        """

        headers = {'X-Project-Id': dummy_project_id}
        resp, consumer_dat = self.consumer_behaviors.delete_consumer(
            None, self.container_ref, extra_headers=headers, use_auth=False
        )

        self.assertEqual(401, resp.status_code)
