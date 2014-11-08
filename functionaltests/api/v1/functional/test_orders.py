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
from functionaltests.api.v1.behaviors import secret_behaviors
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
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_order_defaults_wout_name(self):
        """Create an order without the name attribute."""

        # create order with no name
        test_model = order_models.OrderModel(**order_create_defaults_data)
        overrides = {"name": None}
        test_model.override_values(**overrides)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_w_empty_name(self):
        """Create an order the name attribute an empty string."""

        # create order with empty name
        test_model = order_models.OrderModel(**order_create_defaults_data)
        overrides = {"name": ""}
        test_model.override_values(**overrides)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order was created successfully
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('negative')
    def test_get_order_defaults_that_doesnt_exist(self):
        """Covers case of getting a non-existent order."""

        # try to get a non-existent order
        order_resp = self.behaviors.get_order("a ref that does not exist")

        # verify that the order get failed
        self.assertEqual(order_resp.status_code, 404)

    @testcase.attr('negative')
    def test_create_order_defaults_w_invalid_content_type(self):
        """Covers creating order with invalid content-type header."""

        # create order with empty name
        test_model = order_models.OrderModel(**order_create_defaults_data)
        extra_headers = {"Content-Type": "crypto/boom"}
        create_resp, order_ref = self.behaviors.create_order(
            test_model, extra_headers=extra_headers)

        # verify that the order creation failed
        self.assertEqual(create_resp.status_code, 415)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_nones(self):
        """Covers order creation with empty JSON."""

        # create an order with empty data
        test_model = order_models.OrderModel(**order_create_nones_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order creation failed
        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_empty_entries(self):
        """Covers order creation with empty JSON."""

        # create an order with empty data
        test_model = order_models.OrderModel()
        overrides = {"name": "", "algorithm": "", "mode": "",
                     "bit_length": "", "payload_content_type": ""}

        test_model.override_values(**overrides)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        # verify that the order creation failed
        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_check_empty_name(self):
        """Create order with empty meta name.

        The resulting secret name should be a UUID.
        """

        # first create an order with defaults
        test_model = order_models.OrderModel(**order_create_defaults_data)
        overrides = {"meta": {"name": "", "algorithm": "aes",
                              "bit_length": 256, "mode": "cbc",
                              "payload_content_type": "text/plain"}}
        test_model.override_values(**overrides)
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

        # verify the new secret's name matches the name in the secret ref
        # in the newly created order.
        secret_id_from_ref = utils.get_id_from_ref(order_resp.model.secret_ref)
        secret_resp = self.secret_behaviors.get_secret_metadata(
            order_resp.model.secret_ref)
        self.assertEqual(secret_resp.status_code, 200)
        self.assertGreater(len(secret_id_from_ref), 0)
        self.assertEqual(secret_resp.model.name, secret_id_from_ref)
