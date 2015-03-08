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

order_repo = repositories.get_order_repository()


class WhenCreatingOrdersUsingOrdersResource(utils.BarbicanAPIBaseTestCase):
    generic_key_meta = {
        'name': 'secretname',
        'algorithm': 'AES',
        'bit_length': 256,
        'mode': 'cbc',
        'payload_content_type': 'application/octet-stream'
    }

    def test_can_create_a_new_order(self):
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=self.generic_key_meta
        )
        self.assertEqual(resp.status_int, 202)

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

        self.assertEqual(resp.status_int, 202)

    def test_order_creation_should_fail_without_a_type(self):
        resp, _ = create_order(
            self.app,
            meta=self.generic_key_meta,
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 400)

    def test_order_creation_should_fail_without_metadata(self):
        resp, _ = create_order(
            self.app,
            order_type='key',
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 400)

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

        self.assertEqual(resp.status_int, 400)

    def test_order_creation_should_fail_with_bogus_content(self):
        resp = self.app.post(
            '/orders/',
            'random_stuff',
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_order_creation_should_fail_with_empty_dict(self):
        resp = self.app.post_json(
            '/orders/',
            {},
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_order_creation_should_fail_without_content_type_header(self):
        resp = self.app.post(
            '/orders/',
            'doesnt matter. headers are validated first',
            expect_errors=True,
        )
        self.assertEqual(resp.status_int, 415)


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

    return (resp, created_uuid)
