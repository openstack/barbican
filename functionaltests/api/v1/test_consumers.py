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

create_consumer_data = {
    "name": "consumername",
    "URL": "consumerURL"
}

create_consumer_data_for_delete = {
    "name": "consumername2",
    "URL": "consumerURL2"
}

create_consumer_data_for_recreate = {
    "name": "consumername3",
    "URL": "consumerURL3"
}

create_consumer_data_for_idempotency = {
    "name": "consumername4",
    "URL": "consumerURL4"
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

    def setUp(self):
        super(ConsumersTestCase, self).setUp()
        # Set up two secrets
        secret_json_data = json.dumps(create_secret_data)
        project_id = self.client.project_id
        resp, body = self.client.post(
            '{0}/secrets'.format(project_id), secret_json_data, headers={
            'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        secret_ref_1 = returned_data['secret_ref']
        self.assertIsNotNone(secret_ref_1)
        resp, body = self.client.post(
            '{0}/secrets'.format(project_id), secret_json_data, headers={
            'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        secret_ref_2 = returned_data['secret_ref']
        self.assertIsNotNone(secret_ref_2)

        # Create a container with our secrets
        create_container_data['secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_data['secret_refs'][1]['secret_ref'] = secret_ref_2
        container_json_data = json.dumps(create_container_data)
        resp, body = self.client.post(
            '{0}/containers'.format(project_id), container_json_data,
            headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        container_ref = returned_data['container_ref']
        self.assertIsNotNone(container_ref)
        self.container_id = container_ref.split('/')[-1]

    def test_create_consumer(self):
        """Covers consumer creation.  All of the data needed to
        create the consumer is provided in a single POST.
        """
        json_data = json.dumps(create_consumer_data)
        project_id = self.client.project_id
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data, consumer_data)

    def test_delete_consumer(self):
        """Covers consumer deletion.  A consumer is first created, and then
        the consumer is deleted and verified to no longer exist.
        """
        json_data = json.dumps(create_consumer_data_for_delete)
        project_id = self.client.project_id

        #Register the consumer once
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data_for_delete, consumer_data)

        #Delete the consumer
        resp, body = self.client.delete(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            body=json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertNotIn(create_consumer_data_for_delete, consumer_data)

    def test_recreate_consumer(self):
        """Covers consumer deletion.  A consumer is first created, and then
        the consumer is deleted and verified to no longer exist.
        """
        json_data = json.dumps(create_consumer_data_for_recreate)
        project_id = self.client.project_id

        #Register the consumer once
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data_for_recreate, consumer_data)

        #Delete the consumer
        resp, body = self.client.delete(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            body=json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertNotIn(create_consumer_data_for_recreate, consumer_data)

        #Register the consumer again
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data_for_recreate, consumer_data)

    def test_create_consumer_is_idempotent(self):
        """Covers consumer deletion.  A consumer is first created, and then
        the consumer is deleted and verified to no longer exist.
        """
        json_data = json.dumps(create_consumer_data_for_idempotency)
        project_id = self.client.project_id

        #Register the consumer once
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data_for_idempotency, consumer_data)

        #Register the consumer again, without deleting it first
        resp, body = self.client.post(
            '{0}/containers/{1}/consumers'.format(project_id,
                                                  self.container_id),
            json_data, headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        consumer_data = returned_data['consumers']
        self.assertIsNotNone(consumer_data)
        self.assertIn(create_consumer_data_for_idempotency, consumer_data)
        count = consumer_data.count(create_consumer_data_for_idempotency)
        self.assertEqual(1, count)
