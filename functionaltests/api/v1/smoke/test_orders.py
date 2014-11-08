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
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.models import order_models


order_create_defaults_data = {
    'type': 'key',
    "meta": {
        "name": "barbican functional test secret name",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream",
    }
}

# Any field with None will be created in the model with None as the value
# but will be omitted in the final request (via the requests package)
# to the server.
#
# Given that fact, order_create_nones_data is effectively an empty json request
# to the server.
order_create_nones_data = {
    'type': None,
    "meta": {
        "name": None,
        "algorithm": None,
        "bit_length": None,
        "mode": None,
        "payload_content_type": None,
    }
}


@utils.parameterized_test_case
class OrdersTestCase(base.TestCase):

    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_order_defaults(self):
        """Covers simple order creation."""

        # first create an order
        test_model = order_models.OrderModel(**order_create_defaults_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_get_order_defaults_metadata(self):
        """Covers order metadata.

        Assumes that the order status will be active or pending.
        """

        # first create an order
        test_model = order_models.OrderModel(**order_create_defaults_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

        # given the order href, retrieve the order
        order_resp = self.behaviors.get_order(order_ref)

        # verify that the get was successful
        self.assertEqual(order_resp.status_code, 200)
        self.assertTrue(order_resp.model.status == "ACTIVE" or
                        order_resp.model.status == "PENDING")

        # verify the metadata
        self.assertEqual(order_resp.model.meta.get('name'),
                         test_model.meta.get('name'))
        self.assertEqual(order_resp.model.meta.get('mode'),
                         test_model.meta.get('mode'))
        self.assertEqual(order_resp.model.meta.get('algorithm'),
                         test_model.meta.get('algorithm'))
        self.assertEqual(order_resp.model.meta.get('bit_length'),
                         test_model.meta.get('bit_length'))

    @testcase.attr('positive')
    def test_get_order_defaults(self):
        """Covers getting an order.

         Assumes that the order status will be active or pending.
        """

        # create an order
        test_model = order_models.OrderModel(**order_create_defaults_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

        # get the order
        order_resp = self.behaviors.get_order(order_ref)

        # verify the order
        self.assertEqual(order_resp.status_code, 200)
        self.assertIsNotNone(order_resp.model.secret_ref)
        self.assertIsNotNone(order_resp.model.order_ref)
        self.assertEqual(order_resp.model.type, 'key')
        self.assertTrue(order_resp.model.status == "ACTIVE" or
                        order_resp.model.status == "PENDING")

    @testcase.attr('positive')
    def test_delete_order_defaults(self):
        """Covers simple order deletion."""

        # create an order
        test_model = order_models.OrderModel(**order_create_defaults_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # delete the order
        delete_resp = self.behaviors.delete_order(order_ref)

        # verify the delete
        self.assertEqual(delete_resp.status_code, 204)

    @testcase.attr('positive')
    def test_get_orders_defaults(self):
        """Covers getting a list of orders."""

        # create 11 orders
        test_model = order_models.OrderModel(**order_create_defaults_data)
        for i in xrange(0, 11):
            create_resp, order_ref = self.behaviors.create_order(test_model)
            self.assertEqual(create_resp.status_code, 202)
            self.assertIsNotNone(order_ref)

        # get a list of orders
        limit = 7
        offset = 0
        resp, orders_list, next_ref, prev_ref = self.behaviors.get_orders(
            limit=limit, offset=offset)

        # verify that the get for the list was successful
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(orders_list), limit)
        self.assertIsNotNone(next_ref)
        self.assertIsNone(prev_ref)
