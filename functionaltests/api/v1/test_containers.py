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
import json
import re

from tempest import exceptions

from functionaltests.api import base

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


class ContainersTestCase(base.TestCase):

    def _create_a_secret(self):
        secret_json_data = json.dumps(create_secret_data)
        resp, body = self.client.post(
            '/secrets',
            secret_json_data,
            headers={'content-type': 'application/json'}
        )
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        secret_ref = returned_data.get('secret_ref')
        self.assertIsNotNone(secret_ref)
        return secret_ref

    def _get_a_secret(self, secret_id):
        resp, body = self.client.get(
            '/secrets/{0}'.format(secret_id),
            headers={'content-type': 'application/json'}
        )
        self.assertEqual(resp.status, 200)
        return json.loads(body)

    def _create_a_container(self):
        json_data = json.dumps(create_container_data)
        resp, body = self.client.post(
            '/containers', json_data,
            headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        container_ref = returned_data['container_ref']
        self.assertIsNotNone(container_ref)
        return container_ref

    def _get_a_container(self, container_id):
        resp, body = self.client.get(
            '/containers/{0}'.format(container_id),
            headers={'content-type': 'application/json'}
        )
        self.assertEqual(resp.status, 200)
        self.assertIsNotNone(body)
        return json.loads(body)

    def _get_container_list(self):
        resp, body = self.client.get(
            '/containers/',
            headers={'content-type': 'application/json'}
        )
        self.assertEqual(resp.status, 200)
        return json.loads(body)

    def _delete_a_container(self, container_id):
        resp, body = self.client.delete(
            '/containers/{0}'.format(container_id), headers={}
        )
        self.assertEqual(resp.status, 204)

    def setUp(self):
        super(ContainersTestCase, self).setUp()
        # Set up two secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()

        create_container_data['secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_data['secret_refs'][1]['secret_ref'] = secret_ref_2

        self.secret_id_1 = secret_ref_1.split('/')[-1]
        self.secret_id_2 = secret_ref_2.split('/')[-1]

    def test_create_container(self):
        """Covers container creation.

        All of the data needed to create the container is provided in a
        single POST.
        """
        container_ref = self._create_a_container()
        self.assertIsNotNone(container_ref)

    def test_delete_container(self):
        """Covers container deletion.

        A container is first created, and then the container is deleted
        and verified to no longer exist.
        """
        # Create the container
        container_ref = self._create_a_container()
        container_id = container_ref.split('/')[-1]

        # Delete the container
        self._delete_a_container(container_id)

        # Verify container is gone
        self.assertRaises(
            exceptions.NotFound, self.client.get,
            '/containers/{0}'.format(container_id),
            headers={'content-type': 'application/json'}
        )

        # Verify the Secrets from the container still exist
        self._get_a_secret(self.secret_id_1)
        self._get_a_secret(self.secret_id_2)

    def test_get_container(self):
        """Covers container retrieval.

        A container is first created, and then the container is retrieved.
        """
        # Create a container
        container_ref = self._create_a_container()
        container_id = container_ref.split('/')[-1]

        # Get the container
        self._get_a_container(container_id)

    def test_list_containers(self):
        """Covers listing containers.

        A container is first created, and then
        we check the container list to make sure it has a non-zero total and
        has a `containers` element.
        """
        # Create a container
        self._create_a_container()

        # Get the container list
        list_data = self._get_container_list()
        self.assertGreaterEqual(list_data.get('total'), 1)
        self.assertIsNotNone(list_data.get('containers'))

    def test_containers_secret_refs_correctly_formatted(self):
        """Correctly formatted secret refs in a container

        Create a container (so we are guaranteed to have at least one), then
        retrieve that container and check the secret_ref formatting to make
        sure "secret_ref" attributes contain proper HATEOAS URIs. Then do a
        container list and verify the same for each container in the list.
        """
        secret_ref_pattern = re.compile(
            '(http[s]?://.*/secrets/)([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-'
            '[89aAbB][a-f0-9]{3}-[a-f0-9]{12})')
        # Create a container
        container_ref = self._create_a_container()
        container_id = container_ref.split('/')[-1]

        # Get the container
        container_data = self._get_a_container(container_id)
        secret_refs = container_data.get('secret_refs')
        self.assertIsNotNone(secret_refs)

        # Check the secret_refs
        for ref in secret_refs:
            self.assertIsNotNone(
                secret_ref_pattern.match(str(ref.get('secret_ref')))
            )

        # Get the container list
        containers = self._get_container_list().get('containers')

        # Check the secret_refs for all containers in the list
        for cont in containers:
            secret_refs = cont.get('secret_refs')
            for ref in secret_refs:
                self.assertIsNotNone(
                    secret_ref_pattern.match(str(ref.get('secret_ref')))
                )
