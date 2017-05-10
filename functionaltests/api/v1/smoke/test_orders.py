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
import time

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import order_models


def get_default_order_create_data():
    return {'type': 'key',
            "meta": {
                "name": "barbican functional test secret name",
                "algorithm": "aes",
                "bit_length": 256,
                "mode": "cbc",
            }
            }


# Any field with None will be created in the model with None as the value
# but will be omitted in the final request (via the requests package)
# to the server.
#
# Given that fact, order_create_nones_data is effectively an empty json request
# to the server.

def get_default_order_create_all_none_data():
    return {
        'type': None,
        "meta": {
            "name": None,
            "algorithm": None,
            "bit_length": None,
            "mode": None,
        }
    }


@utils.parameterized_test_case
class OrdersTestCase(base.TestCase):

    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)

        self.create_default_data = get_default_order_create_data()
        self.create_all_none_data = get_default_order_create_all_none_data()

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    def wait_for_order(self, order_resp, order_ref):
        # Make sure we have an active order
        time_count = 1
        while order_resp.model.status != "ACTIVE" and time_count <= 4:
            time.sleep(1)
            time_count += 1
            order_resp = self.behaviors.get_order(order_ref)

    @testcase.attr('positive')
    def test_order_create(self):
        """Covers simple order creation."""

        # first create an order
        test_model = order_models.OrderModel(**self.create_default_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_order_get_metadata(self):
        """Covers order metadata.

        Assumes that the order status will be active or pending.
        """

        # first create an order
        test_model = order_models.OrderModel(**self.create_default_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        # given the order href, retrieve the order
        order_resp = self.behaviors.get_order(order_ref)

        # verify that the get was successful
        self.assertEqual(200, order_resp.status_code)
        self.assertTrue(order_resp.model.status == "ACTIVE" or
                        order_resp.model.status == "PENDING")

        # verify the metadata
        self.assertEqual(test_model.meta.get('name'),
                         order_resp.model.meta.get('name'))
        self.assertEqual(test_model.meta.get('mode'),
                         order_resp.model.meta.get('mode'))
        self.assertEqual(test_model.meta.get('algorithm'),
                         order_resp.model.meta.get('algorithm'))
        self.assertEqual(test_model.meta.get('bit_length'),
                         order_resp.model.meta.get('bit_length'))

    @testcase.attr('positive')
    def test_order_get(self):
        """Covers getting an order.

         Assumes that the order status will be active or pending.
        """

        # create an order
        test_model = order_models.OrderModel(**self.create_default_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        # get the order
        order_resp = self.behaviors.get_order(order_ref)

        # verify the order
        self.assertEqual(200, order_resp.status_code)
        self.assertIsNotNone(order_resp.model.order_ref)
        self.assertEqual('key', order_resp.model.type)
        self.assertTrue(order_resp.model.status == "ACTIVE" or
                        order_resp.model.status == "PENDING")

    @testcase.attr('positive')
    def test_order_delete(self):
        """Covers simple order deletion."""

        # create an order
        test_model = order_models.OrderModel(**self.create_default_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        # get the secret ref
        order_resp = self.behaviors.get_order(order_ref)
        secret_ref = order_resp.model.secret_ref

        # delete the order
        delete_resp = self.behaviors.delete_order(order_ref)

        # clean up the secret that was created
        self.secret_behaviors.delete_secret(secret_ref)

        # verify the delete
        self.assertEqual(204, delete_resp.status_code)

    @testcase.attr('positive')
    def test_orders_get(self):
        """Covers getting a list of orders."""

        # create 11 orders
        test_model = order_models.OrderModel(**self.create_default_data)
        for i in range(0, 11):
            create_resp, order_ref = self.behaviors.create_order(test_model)
            self.assertEqual(202, create_resp.status_code)
            self.assertIsNotNone(order_ref)

        # get a list of orders
        limit = 7
        offset = 0
        resp, orders_list, next_ref, prev_ref = self.behaviors.get_orders(
            limit=limit, offset=offset)

        # verify that the get for the list was successful
        self.assertEqual(200, resp.status_code)
        self.assertEqual(limit, len(orders_list))
        self.assertIsNotNone(next_ref)
        self.assertIsNone(prev_ref)
