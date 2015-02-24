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
import copy
import json
import sys

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
        self.default_data = copy.deepcopy(order_create_defaults_data)
        self.nones_data = copy.deepcopy(order_create_nones_data)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_order_defaults_wout_name(self):
        """Create an order without the name attribute."""

        test_model = order_models.OrderModel(**self.default_data)
        test_model.name = None
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_w_empty_name(self):
        """Create an order the name attribute an empty string."""

        test_model = order_models.OrderModel(**self.default_data)
        test_model.name = ""
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_payload_content_type_none(self):
        """Covers creating orders with various valid payload content types."""
        test_model = order_models.OrderModel(**self.default_data)
        del test_model.meta['payload_content_type']

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_check_empty_name(self):
        """Create order with empty meta name.

        The resulting secret name should be a UUID.
        """

        # first create an order with defaults
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['name'] = ""

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
        secret_resp = self.secret_behaviors.get_secret_metadata(
            order_resp.model.secret_ref)
        self.assertEqual(secret_resp.status_code, 200)
        self.assertEqual(secret_resp.model.name, test_model.meta['name'])

    @testcase.attr('positive')
    def test_order_and_secret_metadata_same(self):
        """Checks that metadata from secret GET and order GET are the same.

        Covers checking that secret metadata from a get on the order and
        secret metadata from a get on the secret are the same. Assumes
        that the order status will be active and not pending.
        """
        test_model = order_models.OrderModel(**self.default_data)

        resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(resp.status_code, 202)

        order_resp = self.behaviors.get_order(order_ref)

        secret_ref = order_resp.model.secret_ref

        secret_resp = self.secret_behaviors.get_secret_metadata(secret_ref)

        self.assertEqual(order_resp.model.meta['name'],
                         secret_resp.model.name,
                         'Names were not the same')
        self.assertEqual(order_resp.model.meta['algorithm'],
                         secret_resp.model.algorithm,
                         'Algorithms were not the same')
        self.assertEqual(order_resp.model.meta['bit_length'],
                         secret_resp.model.bit_length,
                         'Bit lengths were not the same')
        self.assertEqual(order_resp.model.meta['expiration'],
                         secret_resp.model.expiration,
                         'Expirations were not the same')
        self.assertEqual(order_resp.model.meta['mode'],
                         secret_resp.model.mode,
                         'Modes were not the same')

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

        test_model = order_models.OrderModel(**self.default_data)
        extra_headers = {"Content-Type": "crypto/boom"}
        create_resp, order_ref = self.behaviors.create_order(
            test_model, extra_headers=extra_headers)

        self.assertEqual(create_resp.status_code, 415)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_nones(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.nones_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_empty_entries(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.nones_data)
        test_model.meta['name'] = ""
        test_model.meta['algorithm'] = ""
        test_model.meta['mode'] = ""
        test_model.meta['bit_length'] = ""
        test_model.meta['payload_content_type'] = ""

        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_defaults_oversized_strings(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['name'] = base.TestCase.oversized_field
        test_model.meta['algorithm'] = base.TestCase.oversized_field
        test_model.meta['mode'] = base.TestCase.oversized_field

        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_create_order_defaults_error_message_on_invalid_order_create(self):
        """Related Launchpad issue: 1269594."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['payload_content_encoding'] = "blarg!"

        resp, order_ref = self.behaviors.create_order(test_model)
        print(resp.content)

        # Make sure we actually get a message back
        error_msg = json.loads(resp.content).get('title')

        self.assertEqual(resp.status_code, 400)
        self.assertIsNotNone(error_msg)
        self.assertNotEqual(error_msg, 'None')

    @utils.parameterized_dataset({
        '8': [8],
        '64': [64],
        '128': [128],
        '192': [192],
        '256': [256],
        '1024': [1024],
        '2048': [2048],
        '4096': [4096]
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_bit_length(self, bit_length):
        """Covers creating orders with various valid bit lengths."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['bit_length'] = bit_length

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'negative_maxint': [-sys.maxint],
        'negative_7': [-7],
        'negative_1': [-1],
        '0': [0],
        '1': [1],
        '7': [7],
        '129': [129],
        'none': [None],
        'empty': [''],
        'space': [' '],
        'over_signed_small_int': [32768]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_bit_length(self, bit_length):
        """Covers creating orders with various invalid bit lengths."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['bit_length'] = bit_length

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'array': [['array']],
        'int': [123],
        'oversized_payload': [str(base.TestCase.oversized_payload)],
        'standard_payload': ['standard payload'],
        'empty': ['']
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_payload(self, payload):
        """Covers creating orders with various invalid payloads."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['payload'] = payload

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'len_255': [base.TestCase.max_sized_field],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'empty': [""]
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_name(self, name):
        """Covers creating orders with various valid names."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['name'] = name

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_name(self, name):
        """Covers creating orders with various invalid names."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['name'] = name

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'cbc': ['cbc']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_mode(self, mode):
        """Covers creating orders with various valid modes."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['mode'] = mode

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_mode(self, mode):
        """Covers creating orders with various invalid modes."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['mode'] = mode

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'aes': ['aes']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_algorithm(self, algorithm):
        """Covers creating orders with various valid algorithms."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['algorithm'] = algorithm

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_algorithm(self, algorithm):
        """Covers creating orders with various invalid algorithms."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['algorithm'] = algorithm

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'empty': [''],
        'text/plain': ['text/plain'],
        'text_plain_space_charset_utf8': ['text/plain; charset=utf-8'],
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_payload_content_type(self, pct):
        """Covers order creation with various valid payload content types."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['payload_content_type'] = pct

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123],
        'invalid': ['invalid'],
        'oversized_string': [base.TestCase.oversized_field],
        'text': ['text'],
        'text_slash_with_no_subtype': ['text/'],
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_payload_content_type(self, pct):
        """Covers order creation with various invalid payload content types."""
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['payload_content_type'] = pct

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @utils.parameterized_dataset({
        'negative_five_long_expire': {
            'timezone': '-05:00',
            'days': 5},

        'positive_five_long_expire': {
            'timezone': '+05:00',
            'days': 5},

        'negative_one_short_expire': {
            'timezone': '-01',
            'days': 1},

        'positive_one_short_expire': {
            'timezone': '+01',
            'days': 1}
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_expiration(self, **kwargs):
        """Covers creating orders with various valid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['expiration'] = timestamp

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 5},
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_expiration(self, **kwargs):
        """Covers creating orders with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = order_models.OrderModel(**self.default_data)
        test_model.meta['expiration'] = timestamp

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)

    @testcase.attr('positive')
    def test_order_create_change_host_header(self, **kwargs):
        """Create an order with a (possibly) malicious host name in header."""

        test_model = order_models.OrderModel(**order_create_defaults_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, order_ref = self.behaviors.create_order(
            test_model, extra_headers=changed_host_header)

        self.assertEqual(resp.status_code, 202)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegexpMatches(resp.headers['location'], regex)
