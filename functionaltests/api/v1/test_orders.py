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


create_order_data = {
    "secret": {
        "name": "secretname",
        "algorithm": "AES",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream",
    }
}


class OrdersTestCase(base.TestCase):

    def test_create_order(self):
        """Covers order creation.  All of the data needed to
        create the order is provided in a single POST.
        """
        json_data = json.dumps(create_order_data)
        resp, body = self.client.post(
            '/orders', json_data, headers={
                'content-type': 'application/json'})
        self.assertEqual(resp.status, 202)

        returned_data = json.loads(body)
        order_ref = returned_data['order_ref']
        self.assertIsNotNone(order_ref)
