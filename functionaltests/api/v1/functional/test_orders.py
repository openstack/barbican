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

import sys
import time

from oslo_serialization import jsonutils as json
import testtools
from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import order_models

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


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


def get_default_order_create_asymmetric_data():
    return {
        'type': 'asymmetric',
        "meta": {
            "name": "barbican functional test asymmetric secret name",
            "algorithm": "rsa",
            "bit_length": 2048,
            "mode": "cbc",
        }
    }


@utils.parameterized_test_case
class OrdersTestCase(base.TestCase):

    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)

        self.create_default_data = get_default_order_create_data()
        self.create_all_none_data = get_default_order_create_all_none_data()
        self.asymmetric_data = get_default_order_create_asymmetric_data()

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        self.container_behaviors.delete_all_created_containers()
        self.secret_behaviors.delete_all_created_secrets()
        super(OrdersTestCase, self).tearDown()

    def wait_for_order(self, order_resp, order_ref):
        # Make sure we have an active order
        time_count = 1
        while order_resp.model.status != "ACTIVE" and time_count <= 4:
            time.sleep(1)
            time_count += 1
            order_resp = self.behaviors.get_order(order_ref)

    @testcase.attr('positive')
    def test_order_create_w_out_name(self):
        """Create an order without the name attribute."""

        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.name = None
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_order_create_w_empty_name(self):
        """Create an order the name attribute an empty string."""

        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.name = ""
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_orders_create_check_empty_name(self):
        """Create order with empty meta name.

        The resulting secret name should be a UUID.
        """

        # first create an order with defaults
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['name'] = ""

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

        # PENDING orders may take a moment to be processed by the workers
        # when running tests with queue enabled
        self.wait_for_order(order_resp, order_ref)

        # verify the new secret's name matches the name in the secret ref
        # in the newly created order.
        secret_resp = self.secret_behaviors.get_secret_metadata(
            order_resp.model.secret_ref)
        self.assertEqual(200, secret_resp.status_code)
        self.assertEqual(secret_resp.model.name, test_model.meta['name'])

    @testcase.attr('negative')
    def test_order_create_check_secret_payload(self):
        """Create order and check the secret payload.

        Check the secret payload with wrong payload_content_type.
        Should return a 406.
        """
        test_model = order_models.OrderModel(**self.create_default_data)

        resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(200, order_resp.status_code)

        # PENDING orders may take a moment to be processed by the workers
        # when running tests with queue enabled
        self.wait_for_order(order_resp, order_ref)

        secret_ref = order_resp.model.secret_ref

        secret_resp = self.secret_behaviors.get_secret(
            secret_ref, payload_content_type="text/plain")
        self.assertEqual(406, secret_resp.status_code)

    @testcase.attr('positive')
    def test_order_create_check_secret_payload_positive(self):
        """Create order and check the secret payload.

        Check the secret payload with correct payload_content_type.
        """
        test_model = order_models.OrderModel(**self.create_default_data)
        resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)
        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(200, order_resp.status_code)
        # PENDING orders may take a moment to be processed by the workers
        # when running tests with queue enabled
        self.wait_for_order(order_resp, order_ref)
        secret_ref = order_resp.model.secret_ref
        secret_resp = self.secret_behaviors.get_secret(
            secret_ref, payload_content_type="application/octet-stream")
        self.assertEqual(200, secret_resp.status_code)

    @testcase.attr('positive')
    def test_order_and_secret_metadata_same(self):
        """Checks that metadata from secret GET and order GET are the same.

        Covers checking that secret metadata from a get on the order and
        secret metadata from a get on the secret are the same. Assumes
        that the order status will be active and not pending.
        """
        test_model = order_models.OrderModel(**self.create_default_data)

        resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(200, order_resp.status_code)

        # PENDING orders may take a moment to be processed by the workers
        # when running tests with queue enabled
        self.wait_for_order(order_resp, order_ref)

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
    def test_order_get_order_that_doesnt_exist(self):
        """Covers case of getting a non-existent order."""

        # try to get a non-existent order
        order_resp = self.behaviors.get_order("a ref that does not exist")

        # verify that the order get failed
        self.assertEqual(404, order_resp.status_code)

    @testcase.attr('negative')
    def test_order_create_w_invalid_content_type(self):
        """Covers creating order with invalid content-type header."""

        test_model = order_models.OrderModel(**self.create_default_data)
        extra_headers = {"Content-Type": "crypto/boom"}
        create_resp, order_ref = self.behaviors.create_order(
            test_model, extra_headers=extra_headers)

        self.assertEqual(415, create_resp.status_code)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_order_create_all_none(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.create_all_none_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_order_create_empty_entries(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.create_all_none_data)
        test_model.meta['name'] = ""
        test_model.meta['algorithm'] = ""
        test_model.meta['mode'] = ""
        test_model.meta['bit_length'] = ""
        test_model.meta['payload_content_type'] = ""

        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_order_create_oversized_strings(self):
        """Covers order creation with empty JSON."""

        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['name'] = base.TestCase.oversized_field
        test_model.meta['algorithm'] = base.TestCase.oversized_field
        test_model.meta['mode'] = base.TestCase.oversized_field

        create_resp, order_ref = self.behaviors.create_order(test_model)

        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)

    @testcase.attr('negative')
    def test_order_create_error_message_on_invalid_order_create(self):
        """Related Launchpad issue: 1269594."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['payload'] = "blarg!"

        resp, order_ref = self.behaviors.create_order(test_model)

        # Make sure we actually get a message back
        error_msg = json.loads(resp.content).get('title')

        self.assertEqual(400, resp.status_code)
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
    def test_order_create_valid_bit_length(self, bit_length):
        """Covers creating orders with various valid bit lengths."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['bit_length'] = bit_length

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'negative_maxint': [-sys.maxsize],
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
    def test_order_create_invalid_bit_length(self, bit_length):
        """Covers creating orders with various invalid bit lengths."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['bit_length'] = bit_length

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @utils.parameterized_dataset({
        'array': [['array']],
        'int': [123],
        'oversized_payload': [str(base.TestCase.oversized_payload)],
        'standard_payload': ['standard payload'],
        'empty': ['']
    })
    @testcase.attr('negative')
    def test_order_create_invalid_payload(self, payload):
        """Covers creating orders with various invalid payloads."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['payload'] = payload

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'len_255': [base.TestCase.max_sized_field],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'empty': [""]
    })
    @testcase.attr('positive')
    def test_order_create_valid_name(self, name):
        """Covers creating orders with various valid names."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['name'] = name

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_order_create_invalid_name(self, name):
        """Covers creating orders with various invalid names."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['name'] = name

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @utils.parameterized_dataset({
        'cbc': ['cbc']
    })
    @testcase.attr('positive')
    def test_order_create_valid_mode(self, mode):
        """Covers creating orders with various valid modes."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['mode'] = mode

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_order_create_with_no_mode(self):
        """Covers creating orders with no mode specified."""
        test_model = order_models.OrderModel(**self.create_default_data)
        del test_model.meta['mode']

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_order_create_invalid_mode(self, mode):
        """Covers creating orders with various invalid modes."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['mode'] = mode

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @utils.parameterized_dataset({
        'aes': ['aes']
    })
    @testcase.attr('positive')
    def test_order_create_valid_algorithm(self, algorithm):
        """Covers creating orders with various valid algorithms."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['algorithm'] = algorithm

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_order_create_invalid_algorithm(self, algorithm):
        """Covers creating orders with various invalid algorithms."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['algorithm'] = algorithm

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @utils.parameterized_dataset({
        'empty': [''],
        'text/plain': ['text/plain'],
        'text_plain_space_charset_utf8': ['text/plain; charset=utf-8'],
    })
    @testcase.attr('positive')
    def test_order_create_valid_payload_content_type(self, pct):
        """Covers order creation with various valid payload content types."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['payload_content_type'] = pct

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'int': [123],
        'invalid': ['invalid'],
        'oversized_string': [base.TestCase.oversized_field],
        'text': ['text'],
        'text_slash_with_no_subtype': ['text/'],
    })
    @testcase.attr('negative')
    def test_order_create_invalid_payload_content_type(self, pct):
        """Covers order creation with various invalid payload content types."""
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['payload_content_type'] = pct

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

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
    def test_order_create_valid_expiration(self, **kwargs):
        """Covers creating orders with various valid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['expiration'] = timestamp

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    @utils.parameterized_dataset({
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 5},
    })
    @testcase.attr('negative')
    def test_order_create_invalid_expiration(self, **kwargs):
        """Covers creating orders with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = order_models.OrderModel(**self.create_default_data)
        test_model.meta['expiration'] = timestamp

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)

    @testcase.skipIf(not base.conf_host_href_used, 'response href using '
                     'wsgi request instead of CONF.host_href')
    @testcase.attr('positive')
    def test_order_create_change_host_with_header_not_allowed(self, **kwargs):
        """Create an order with a (possibly) malicious host name in header."""

        test_model = order_models.OrderModel(**self.create_default_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, order_ref = self.behaviors.create_order(
            test_model, extra_headers=changed_host_header)

        self.assertEqual(202, resp.status_code)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegex(resp.headers['location'], regex)

    @testcase.skipIf(base.conf_host_href_used, 'response href using '
                     'CONF.host_href instead of wsgi request')
    @testcase.attr('positive')
    def test_order_get_change_host_with_header_allowed(self, **kwargs):
        """Get an order with a alternative proxy host name in header."""

        test_model = order_models.OrderModel(**self.create_default_data)

        another_proxy_hostname = 'proxy2.server.com'
        changed_host_header = {'Host': another_proxy_hostname}

        # In test, cannot pass different host header during create as returned
        # order_ref in response contains that host in url. That url is
        # used in deleting that order during cleanup step.
        resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)

        order_resp = self.behaviors.get_order(
            order_ref, extra_headers=changed_host_header)
        # Assert that returned href has provided proxy hostname
        regex = '.*{0}.*'.format(another_proxy_hostname)
        self.assertRegex(order_resp.model.order_ref, regex)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_vault_enabled() or utils.is_pkcs11_enabled(),
                      "Vault does not support this operation")
    def test_encryption_using_generated_key(self):
        """Tests functionality of a generated asymmetric key pair."""
        test_model = order_models.OrderModel(**self.asymmetric_data)
        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(200, order_resp.status_code)

        container_resp = self.container_behaviors.get_container(
            order_resp.model.container_ref)
        self.assertEqual(200, container_resp.status_code)

        secret_dict = {}
        for secret in container_resp.model.secret_refs:
            self.assertIsNotNone(secret.secret_ref)
            secret_resp = self.secret_behaviors.get_secret(
                secret.secret_ref, "application/octet-stream")
            self.assertIsNotNone(secret_resp)
            secret_dict[secret.name] = secret_resp.content

        private_key = serialization.load_pem_private_key(
            secret_dict['private_key'],
            password=None,
            backend=backends.default_backend()
        )
        public_key = serialization.load_pem_public_key(
            secret_dict['public_key'],
            backend=backends.default_backend()
        )

        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

        message = b'plaintext message'
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        self.assertEqual(message, plaintext)


class OrdersPagingTestCase(base.PagingTestCase):

    def setUp(self):
        super(OrdersPagingTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)

        # make a local mutable copy of the default data to prevent
        # possible data contamination
        self.create_default_data = get_default_order_create_data()

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersPagingTestCase, self).tearDown()

    def create_model(self):
        return order_models.OrderModel(**self.create_default_data)

    def create_resources(self, count=0, model=None):
        for x in range(0, count):
            self.behaviors.create_order(model)

    def get_resources(self, limit=10, offset=0, filter=None):
        return self.behaviors.get_orders(limit=limit, offset=offset,
                                         filter=filter)

    def set_filter_field(self, unique_str, model):
        '''Set the meta field which we use in the get_resources '''
        model.meta['name'] = unique_str


class OrdersUnauthedTestCase(base.TestCase):

    def setUp(self):
        super(OrdersUnauthedTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)

        self.create_default_data = get_default_order_create_data()
        self.dummy_order_ref = 'orders/dummy-7b86-4071-935d-ef6b83729200'
        self.dummy_project_id = 'dummy'

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        self.container_behaviors.delete_all_created_containers()
        self.secret_behaviors.delete_all_created_secrets()
        super(OrdersUnauthedTestCase, self).tearDown()

    @testcase.attr('negative', 'security')
    def test_order_create_unauthed_no_proj_id(self):
        """Attempt to create an order without a token or project id

        Should return 401
        """

        model = order_models.OrderModel(self.create_default_data)
        resp, order_ref = self.behaviors.create_order(model, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_get_unauthed_no_proj_id(self):
        """Attempt to get an order without a token or project id

        Should return 401
        """

        resp = self.behaviors.get_order(self.dummy_order_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_get_order_list_unauthed_no_proj_id(self):
        """Attempt to get the list of orders without a token or project id

        Should return 401
        """

        resp, orders, next_ref, prev_ref = self.behaviors.get_orders(
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_delete_unauthed_no_proj_id(self):
        """Attempt to delete an order without a token or project id

        Should return 401
        """

        resp = self.behaviors.delete_order(
            self.dummy_order_ref, expected_fail=True, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_create_unauthed_with_proj_id(self):
        """Attempt to create an order with a project id, but no token

        Should return 401
        """

        model = order_models.OrderModel(self.create_default_data)
        headers = {'X-Project-Id': self.dummy_project_id}
        resp, order_ref = self.behaviors.create_order(
            model, extra_headers=headers, use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_get_unauthed_with_proj_id(self):
        """Attempt to get an order with a project id, but no token

        Should return 401
        """

        headers = {'X-Project-Id': self.dummy_project_id}
        resp = self.behaviors.get_order(
            self.dummy_order_ref, extra_headers=headers, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_get_order_list_unauthed_with_proj_id(self):
        """Attempt to get the list of orders with a project id, but no token

        Should return 401
        """

        headers = {'X-Project-Id': self.dummy_project_id}
        resp, orders, next_ref, prev_ref = self.behaviors.get_orders(
            extra_headers=headers, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_order_delete_unauthed_with_proj_id(self):
        """Attempt to delete an order with a project id, but no token

        Should return 401
        """

        headers = {'X-Project-Id': self.dummy_project_id}
        resp = self.behaviors.delete_order(
            self.dummy_order_ref, extra_headers=headers, expected_fail=True,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)
