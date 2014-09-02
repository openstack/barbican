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
import os

from functionaltests.api import base


one_phase_create_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

two_phase_create_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
}

two_phase_payload_data = {
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}


class SecretsTestCase(base.TestCase):

    def test_create_secret_single_phase(self):
        """Covers single phase secret creation.

        All of the data needed to create the secret, including payload,
        is provided in a single POST.
        """
        json_data = json.dumps(one_phase_create_data)
        resp, body = self.client.post(
            '/secrets', json_data, headers={
                'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        secret_ref = returned_data['secret_ref']
        self.assertIsNotNone(secret_ref)

    def test_create_secret_two_phase(self):
        """Covers two phase secret creation.

        The first call, a POST, provides the metadata about the
        secret - everything except the payload. A subsequent call (PUT)
        provides the payload.
        """
        # phase 1 - POST secret without payload
        json_data = json.dumps(two_phase_create_data)
        resp, body = self.client.post(
            '/secrets', json_data, headers={
                'content-type': 'application/json'})
        self.assertEqual(resp.status, 201)

        returned_data = json.loads(body)
        secret_ref = returned_data['secret_ref']
        self.assertIsNotNone(secret_ref)

        secret_id = os.path.split(secret_ref)[1]
        self.assertIsNotNone(secret_id)

        # phase 2 - provide (PUT) the secret payload
        json_data = json.dumps(two_phase_payload_data)
        resp, body = self.client.post(
            '/secrets/{0}'.format(secret_id), json_data,
            headers={'content-type': 'application/json'})
        self.assertEqual(resp.status, 200)

        returned_data = json.loads(body)
        secret_ref = returned_data['secret_ref']
        self.assertIsNotNone(secret_ref)
