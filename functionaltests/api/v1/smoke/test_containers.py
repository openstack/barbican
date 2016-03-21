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
from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models

create_secret_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

create_container_defaults_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        },
        {
            "name": "secret3"
        }
    ]
}

create_container_rsa_data = {
    "name": "rsacontainer",
    "type": "rsa",
    "secret_refs": [
        {
            "name": "public_key",
        },
        {
            "name": "private_key",
        },
        {
            "name": "private_key_passphrase"
        }
    ]
}

create_container_empty_data = {
    "name": None,
    "type": "generic",
    "secret_refs": []
}


@utils.parameterized_test_case
class ContainersTestCase(base.TestCase):

    def setUp(self):
        super(ContainersTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.behaviors = container_behaviors.ContainerBehaviors(
            self.client)

        # Set up three secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()
        secret_ref_3 = self._create_a_secret()

        create_container_defaults_data[
            'secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_defaults_data[
            'secret_refs'][1]['secret_ref'] = secret_ref_2
        create_container_defaults_data[
            'secret_refs'][2]['secret_ref'] = secret_ref_3

        create_container_rsa_data[
            'secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_rsa_data[
            'secret_refs'][1]['secret_ref'] = secret_ref_2
        create_container_rsa_data[
            'secret_refs'][2]['secret_ref'] = secret_ref_3

        self.secret_id_1 = secret_ref_1.split('/')[-1]
        self.secret_id_2 = secret_ref_2.split('/')[-1]
        self.secret_id_3 = secret_ref_3.split('/')[-1]

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.behaviors.delete_all_created_containers()
        super(ContainersTestCase, self).tearDown()

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_defaults_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def _get_a_secret(self, secret_id):
        resp = self.client.get('secrets/{0}'.format(secret_id))
        self.assertEqual(resp.status_code, 200)
        return resp.json()

    @testcase.attr('positive')
    def test_container_create_empty(self):
        """Covers creating an empty generic container."""
        test_model = container_models.ContainerModel(
            **create_container_empty_data)

        resp, container_ref = self.behaviors.create_container(
            test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

    @testcase.attr('positive')
    def test_container_create_defaults(self):
        """Covers creating a container with three secret refs."""
        test_model = container_models.ContainerModel(
            **create_container_defaults_data)

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

    @testcase.attr('positive')
    def test_container_create_rsa(self):
        """Create an RSA container with expected secret refs."""
        test_model = container_models.ContainerModel(
            **create_container_rsa_data)

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

    @utils.parameterized_dataset({
        'alphanumeric': ['a2j3j6ll9'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'len_255': [str(bytearray().zfill(255))],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'empty': ['']
    })
    @testcase.attr('positive')
    def test_container_get_defaults_w_valid_name(self, name):
        """Covers getting a generic container with a three secrets."""
        test_model = container_models.ContainerModel(
            **create_container_defaults_data)
        overrides = {'name': name}
        test_model.override_values(**overrides)

        secret_refs = []
        for secret_ref in test_model.secret_refs:
            secret_refs.append(secret_ref['secret_ref'])

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

        get_resp = self.behaviors.get_container(container_ref)

        # Verify the response data
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.model.name, test_model.name)
        self.assertEqual(get_resp.model.container_ref, container_ref)
        self.assertEqual(get_resp.model.type, test_model.type)

        # Verify the secret refs in the response
        self.assertEqual(len(get_resp.model.secret_refs), 3)
        self.assertIn(get_resp.model.secret_refs[0].secret_ref, secret_refs)
        self.assertIn(get_resp.model.secret_refs[1].secret_ref, secret_refs)
        self.assertIn(get_resp.model.secret_refs[2].secret_ref, secret_refs)

    @testcase.attr('positive')
    def test_container_get_rsa(self):
        """Covers getting an rsa container."""
        test_model = container_models.ContainerModel(
            **create_container_rsa_data)
        secret_refs = []
        for secret_ref in test_model.secret_refs:
            secret_refs.append(secret_ref['secret_ref'])

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

        get_resp = self.behaviors.get_container(
            container_ref)

        # Verify the response data
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.model.name, "rsacontainer")
        self.assertEqual(get_resp.model.container_ref, container_ref)
        self.assertEqual(get_resp.model.type, "rsa")

        # Verify the secret refs in the response
        self.assertEqual(len(get_resp.model.secret_refs), 3)
        self.assertIn(get_resp.model.secret_refs[0].secret_ref, secret_refs)
        self.assertIn(get_resp.model.secret_refs[1].secret_ref, secret_refs)
        self.assertIn(get_resp.model.secret_refs[2].secret_ref, secret_refs)

    @testcase.attr('positive')
    def test_containers_get_defaults(self):
        """Covers getting a list of containers."""
        limit = 10
        offset = 0
        test_model = container_models.ContainerModel(
            **create_container_defaults_data)
        for i in range(11):
            resp, container_ref = self.behaviors.create_container(test_model)
            self.assertEqual(resp.status_code, 201)
            self.assertGreater(len(container_ref), 0)

        resp, containers, next_ref, prev_ref = self.behaviors.get_containers(
            limit=limit,
            offset=offset
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(containers), limit)
        self.assertIsNone(prev_ref)
        self.assertIsNotNone(next_ref)

    def test_container_delete_defaults(self):
        """Covers deleting a container."""
        test_model = container_models.ContainerModel(
            **create_container_defaults_data)

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        self.assertGreater(len(container_ref), 0)

        del_resp = self.behaviors.delete_container(container_ref)
        self.assertEqual(del_resp.status_code, 204)
        self.assertEqual(len(del_resp.content), 0)
