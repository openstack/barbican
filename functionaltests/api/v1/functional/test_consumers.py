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

create_generic_container_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": []
}

create_cert_container_data = {
    "name": "A Certificate Container",
    "type": "certificate",
    "secret_refs": []
}

dummy_project_id = 'dummy123'


class ConsumersBaseTestCase(base.TestCase):

    def setUp(self):
        super(ConsumersBaseTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client
        )
        self.consumer_behaviors = consumer_behaviors.ConsumerBehaviors(
            self.client
        )

        self.consumer_data = copy.deepcopy(default_consumer_data)

        self.generic_container_ref = self._create_populated_generic_container()

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        super(ConsumersBaseTestCase, self).tearDown()

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)
        return secret_ref

    def _add_secret_ref_to_container(self, container, name, ref):
        container['secret_refs'].append({"name": name, "secret_ref": ref})

    def _create_populated_generic_container(self):
        # Set up two secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()

        # Create a generic container with our secrets

        generic_container_data = copy.deepcopy(create_generic_container_data)

        self._add_secret_ref_to_container(generic_container_data,
                                          'secret_ref_1', secret_ref_1)
        self._add_secret_ref_to_container(generic_container_data,
                                          'secret_ref_2', secret_ref_2)

        container_model = container_models.ContainerModel(
            **generic_container_data
        )

        resp, container_ref = self.container_behaviors.create_container(
            container_model
        )
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(container_ref)

        return container_ref


class ConsumersCertContainerTestCase(ConsumersBaseTestCase):

    def setUp(self):
        super(ConsumersCertContainerTestCase, self).setUp()

        self.container_default_data = copy.deepcopy(create_cert_container_data)
        self.consumer_default_data = copy.deepcopy(default_consumer_data)

    def _create_consumer(self, container_ref):
        self.consumer_test_model = consumer_model.ConsumerModel(
            **self.consumer_default_data)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            self.consumer_test_model, container_ref)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)
        return consumer_data

    def _get_decrypted_secrets_from_container(self, container_href):
        get_resp = self.container_behaviors.get_container(container_href)
        self.assertEqual(get_resp.status_code, 200)

        private_key_ref = get_resp.model.secret_refs[0].secret_ref
        tls_cert_ref = get_resp.model.secret_refs[1].secret_ref
        passphrase_ref = get_resp.model.secret_refs[2].secret_ref
        intermediates_ref = get_resp.model.secret_refs[3].secret_ref

        private_key = self.secret_behaviors.get_secret(
            private_key_ref, 'application/octet-stream')
        tls_cert = self.secret_behaviors.get_secret(
            tls_cert_ref, 'application/octet-stream')
        passphrase = self.secret_behaviors.get_secret(
            passphrase_ref, 'application/octet-stream')
        intermediates = self.secret_behaviors.get_secret(
            intermediates_ref, 'application/octet-stream')

        return private_key, tls_cert, passphrase, intermediates

    def _create_populated_cert_container(self):
        dummy_private_key_ref = self._create_a_secret()
        dummy_tls_certificate_ref = self._create_a_secret()
        dummy_passphrase_ref = self._create_a_secret()
        dummy_intermediates_ref = self._create_a_secret()
        container_ref = self._create_cert_container(dummy_private_key_ref,
                                                    dummy_tls_certificate_ref,
                                                    dummy_passphrase_ref,
                                                    dummy_intermediates_ref)
        return container_ref

    def _create_cert_container(self, private_key_ref, tls_certificate_ref,
                               passphrase_ref=None, intermediates_ref=None):

        container_data = copy.deepcopy(self.container_default_data)
        self._add_secret_ref_to_container(container_data, "certificate",
                                          tls_certificate_ref)
        self._add_secret_ref_to_container(container_data, "private_key",
                                          private_key_ref)

        if passphrase_ref:
            self._add_secret_ref_to_container(container_data,
                                              "private_key_passphrase",
                                              passphrase_ref)

        if intermediates_ref:
            self._add_secret_ref_to_container(container_data, "intermediates",
                                              intermediates_ref)

        test_model = container_models.ContainerModel(
            **container_data)

        resp, container_ref = self.container_behaviors.create_container(
            test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(container_ref)
        return container_ref

    def _deregister_consumer(self, container_ref):
        resp, consumer_data = self.consumer_behaviors.delete_consumer(
            self.consumer_test_model, container_ref
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(consumer_data)
        self.assertNotIn(self.consumer_test_model.name, consumer_data)
        self.assertNotIn(self.consumer_test_model.URL, consumer_data)
        return consumer_data

    @testcase.attr('positive')
    def test_consumer_of_cert_container_full_flow(self):
        """Simulate the typical flow for a consumer of a cert container.

        First, create a container and load it up with a key, cert and
        passphrase.

        Second, register as a consumer for that container

        Third, fetch the data from that container

        Finally, deregister as a consumer for the container
        """

        # create the populated container with a cert
        container_ref = self._create_populated_cert_container()
        self.assertIsNotNone(container_ref)

        # register as a consumer here
        consumer_data = self._create_consumer(container_ref)
        self.assertIsNotNone(consumer_data)
        self.assertEqual(1, len(consumer_data))

        # fetch the cert info from the container
        pk_response, cert_response, passphrase_response, inters_response =\
            self._get_decrypted_secrets_from_container(container_ref)
        self.assertIsNotNone(pk_response)
        self.assertIsNotNone(cert_response)
        self.assertIsNotNone(passphrase_response)
        self.assertIsNotNone(inters_response)

        # deregister as a consumer
        updated_consumer_data = self._deregister_consumer(container_ref)
        self.assertIsNotNone(updated_consumer_data)
        self.assertEqual(0, len(updated_consumer_data))


class ConsumersAuthedTestCase(ConsumersBaseTestCase):

    @testcase.attr('negative', 'security')
    def test_consumer_create_authed(self):
        """Create a consumer as an authenticated user

        Should return 200
        """

        model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_dat = self.consumer_behaviors.create_consumer(
            model, self.generic_container_ref, use_auth=True
        )
        self.assertEqual(200, resp.status_code)


class ConsumersUnauthedTestCase(ConsumersBaseTestCase):

    @testcase.attr('negative', 'security')
    def test_consumer_create_unauthed_no_proj_id(self):
        """Attempt to create a consumer without a token or project id

        Should return 401
        """

        model = consumer_model.ConsumerModel(**self.consumer_data)
        resp, consumer_dat = self.consumer_behaviors.create_consumer(
            model, self.generic_container_ref, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_get_list_unauthed_no_proj_id(self):
        """Attempt to get the list of consumers w/o a token or project id

        Should return 401
        """

        resp, consumers, next_ref, prev_ref = (
            self.consumer_behaviors.get_consumers(
                self.generic_container_ref, use_auth=False
            )
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_consumer_delete_unauthed_no_proj_id(self):
        """Attempt to delete a consumer without a token or project id

        Should return 401
        """

        resp, consumer_dat = self.consumer_behaviors.delete_consumer(
            None, self.generic_container_ref, use_auth=False
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
            model, self.generic_container_ref, extra_headers=headers,
            use_auth=False
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
                self.generic_container_ref, extra_headers=headers,
                use_auth=False
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
            None, self.generic_container_ref, extra_headers=headers,
            use_auth=False
        )

        self.assertEqual(401, resp.status_code)
