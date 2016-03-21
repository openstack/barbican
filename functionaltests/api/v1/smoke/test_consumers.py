# Copyright (c) 2014 Rackspace, Inc.
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


class ConsumersTestCase(base.TestCase):
    default_data = default_consumer_data

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def setUp(self):
        super(ConsumersTestCase, self).setUp()
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
        self.container_behaviors.delete_all_created_containers()
        super(ConsumersTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_consumer_defaults(self):
        """Covers consumer creation.

        All of the data needed to create the consumer is provided in a
        single POST.
        """
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

    @testcase.attr('positive')
    def test_get_consumer_defaults(self):
        """Tests getting a list of consumers for a container."""
        # Create first consumer
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # Create second consumer
        test_model.name = "consumername2"
        test_model.URL = "consumerURL2"

        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # Get list of consumers
        resp, consumers, nref, pref = self.consumer_behaviors.get_consumers(
            self.container_ref
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("consumername", consumers[0].name)
        self.assertIn("consumername2", consumers[1].name)

    @testcase.attr('positive')
    def test_delete_consumer_defaults(self):
        """Covers consumer deletion.

        A consumer is first created, and then the consumer is deleted and
        verified to no longer exist.
        """
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # Delete the consumer
        resp, consumer_data = self.consumer_behaviors.delete_consumer(
            test_model, self.container_ref
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)
        self.assertNotIn(test_model.name, consumer_data)
        self.assertNotIn(test_model.URL, consumer_data)

    @testcase.attr('positive')
    def test_recreate_consumer_defaults(self):
        """Covers consumer recreation."""
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # Delete the consumer
        resp, consumer_data = self.consumer_behaviors.delete_consumer(
            test_model, self.container_ref
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)
        self.assertNotIn(test_model.name, consumer_data)
        self.assertNotIn(test_model.URL, consumer_data)

        # Register the consumer again
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

    @testcase.attr('positive')
    def test_create_consumer_defaults_is_idempotent(self):
        """Covers checking that create consumer is idempotent."""
        # Register the consumer once
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # Register the consumer again, without deleting it first
        test_model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref)

        count = consumer_data.count(self.consumer_data)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)
        self.assertIn(self.consumer_data, consumer_data)
        self.assertEqual(1, count)

    @testcase.attr('positive')
    def test_create_consumer_change_host_header(self, **kwargs):
        """Create a consumer with a (possibly) malicious host name header."""

        test_model = consumer_model.ConsumerModel(**self.consumer_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, consumer_data = self.consumer_behaviors.create_consumer(
            test_model, self.container_ref, extra_headers=changed_host_header)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegexpMatches(resp.headers['location'], regex)
