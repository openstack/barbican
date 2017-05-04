# Copyright (c) 2015 Rackspace, Inc.
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
import os
import uuid

from barbican.model import models
from barbican.model import repositories
from barbican.tests import utils
from oslo_utils import uuidutils


order_repo = repositories.get_order_repository()
project_repo = repositories.get_project_repository()
ca_repo = repositories.get_ca_repository()
project_ca_repo = repositories.get_project_ca_repository()
container_repo = repositories.get_container_repository()

generic_key_meta = {
    'name': 'secretname',
    'algorithm': 'AES',
    'bit_length': 256,
    'mode': 'cbc',
    'payload_content_type': 'application/octet-stream'
}


class WhenCreatingOrdersUsingOrdersResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_a_new_order(self):
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, resp.status_int)

        # Make sure we get a valid uuid for the order
        uuid.UUID(order_uuid)

        order = order_repo.get(order_uuid, self.project_id)

        self.assertIsInstance(order, models.Order)

    def test_order_creation_should_allow_unknown_algorithm(self):
        meta = {
            'bit_length': 128,
            'algorithm': 'unknown'
        }
        resp, _ = create_order(
            self.app,
            order_type='key',
            meta=meta
        )

        self.assertEqual(202, resp.status_int)

    def test_order_creation_should_fail_without_a_type(self):
        resp, _ = create_order(
            self.app,
            meta=generic_key_meta,
            expect_errors=True
        )

        self.assertEqual(400, resp.status_int)

    def test_order_creation_should_fail_without_metadata(self):
        resp, _ = create_order(
            self.app,
            order_type='key',
            expect_errors=True
        )

        self.assertEqual(400, resp.status_int)

    def test_order_create_should_fail_w_unsupported_payload_content_type(self):
        meta = {
            'bit_length': 128,
            'algorithm': 'aes',
            'payload_content_type': 'something_unsupported'
        }
        resp, _ = create_order(
            self.app,
            order_type='key',
            meta=meta,
            expect_errors=True
        )

        self.assertEqual(400, resp.status_int)

    def test_order_creation_should_fail_with_bogus_content(self):
        resp = self.app.post(
            '/orders/',
            'random_stuff',
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_order_creation_should_fail_with_empty_dict(self):
        resp = self.app.post_json(
            '/orders/',
            {},
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_order_creation_should_fail_without_content_type_header(self):
        resp = self.app.post(
            '/orders/',
            'doesn\'t matter. headers are validated first',
            expect_errors=True,
        )
        self.assertEqual(415, resp.status_int)


class WhenGettingOrdersListUsingOrdersResource(utils.BarbicanAPIBaseTestCase):
    def test_can_get_a_list_of_orders(self):
        # Make sure we have atleast one order to created
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, resp.status_int)

        # Get the list of orders
        resp = self.app.get(
            '/orders/',
            headers={'Content-Type': 'application/json'}
        )

        self.assertEqual(200, resp.status_int)
        self.assertIn('total', resp.json)
        self.assertGreater(len(resp.json.get('orders')), 0)

    def test_pagination_attributes_not_available_with_empty_order_list(self):
        params = {'name': 'no_orders_with_this_name'}

        resp = self.app.get(
            '/orders/',
            params
        )

        self.assertEqual(200, resp.status_int)
        self.assertEqual(0, len(resp.json.get('orders')))


class WhenGettingOrDeletingOrders(utils.BarbicanAPIBaseTestCase):
    def test_can_get_order(self):
        # Make sure we have a order to retrieve
        create_resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, create_resp.status_int)

        # Retrieve the order
        get_resp = self.app.get('/orders/{0}/'.format(order_uuid))
        self.assertEqual(200, get_resp.status_int)

    def test_can_delete_order(self):
        # Make sure we have a order to retrieve
        create_resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, create_resp.status_int)

        delete_resp = self.app.delete('/orders/{0}'.format(order_uuid))
        self.assertEqual(204, delete_resp.status_int)

    def test_get_call_on_non_existant_order_should_give_404(self):
        bogus_uuid = uuidutils.generate_uuid()
        resp = self.app.get(
            '/orders/{0}'.format(bogus_uuid),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)

    def test_returns_404_on_get_with_bad_uuid(self):
        resp = self.app.get(
            '/orders/98c876d9-aaac-44e4-8ea8-441932962b05X',
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)

    def test_delete_call_on_non_existant_order_should_give_404(self):
        bogus_uuid = uuidutils.generate_uuid()
        resp = self.app.delete(
            '/orders/{0}'.format(bogus_uuid),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)


class WhenCreatingOrders(utils.BarbicanAPIBaseTestCase):
    def test_should_add_new_order(self):
        order_meta = {
            'name': 'secretname',
            'expiration': '2114-02-28T17:14:44.180394',
            'algorithm': 'AES',
            'bit_length': 256,
            'mode': 'cbc',
            'payload_content_type': 'application/octet-stream'
        }
        create_resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=order_meta
        )
        self.assertEqual(202, create_resp.status_int)

        order = order_repo.get(order_uuid, self.project_id)
        self.assertIsInstance(order, models.Order)
        self.assertEqual('key', order.type)
        self.assertEqual(order_meta, order.meta)

    def test_should_return_400_when_creating_with_empty_json(self):
        resp = self.app.post_json('/orders/', {}, expect_errors=True)
        self.assertEqual(400, resp.status_int,)

    def test_should_return_415_when_creating_with_blank_body(self):
        resp = self.app.post('/orders/', '', expect_errors=True)
        self.assertEqual(415, resp.status_int)


class WhenPerformingUnallowedOperations(utils.BarbicanAPIBaseTestCase):
    def test_should_not_allow_put_orders(self):
        resp = self.app.put_json('/orders/', expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_delete_orders(self):
        resp = self.app.delete('/orders/', expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_post_order_by_id(self):
        # Create generic order so we don't get a 404 on POST
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, resp.status_int)

        resp = self.app.post_json(
            '/orders/{0}'.format(order_uuid),
            {},
            expect_errors=True
        )

        self.assertEqual(405, resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_order(app, order_type=None, meta=None, expect_errors=False):
    # TODO(jvrbanac): Once test resources is split out, refactor this
    # and similar functions into a generalized helper module and reduce
    # duplication.
    request = {
        'type': order_type,
        'meta': meta
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/orders/',
        cleaned_request,
        expect_errors=expect_errors
    )

    created_uuid = None
    if resp.status_int == 202:
        order_ref = resp.json.get('order_ref', '')
        _, created_uuid = os.path.split(order_ref)

    return resp, created_uuid


def create_container(app, name=None, container_type=None, secret_refs=None,
                     expect_errors=False, headers=None):
    request = {
        'name': name,
        'type': container_type,
        'secret_refs': secret_refs if secret_refs else []
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/containers/',
        cleaned_request,
        expect_errors=expect_errors,
        headers=headers
    )

    created_uuid = None
    if resp.status_int == 201:
        container_ref = resp.json.get('container_ref', '')
        _, created_uuid = os.path.split(container_ref)

    return resp, created_uuid
