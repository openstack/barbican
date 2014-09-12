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
from functionaltests.api import base
from functionaltests.api.v1.models import order_models


create_order_data = {
    'type': 'key',
    "meta": {
        "name": "secretname",
        "algorithm": "AES",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream",
    }
}


class OrdersTestCase(base.TestCase):

    def test_create_order(self):
        """Covers order creation.

        All of the data needed to create the order is provided in a
        single POST.
        """
        model = order_models.OrderModel(**create_order_data)
        resp = self.client.post('orders/', request_model=model)
        self.assertEqual(resp.status_code, 202)

        body = resp.json()
        self.assertIsNotNone(body.get('order_ref'))
