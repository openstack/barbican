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

import mock

from barbican.common import resources
from barbican.model import models
from barbican.model import repositories
from barbican.tests import utils

order_repo = repositories.get_order_repository()
project_repo = repositories.get_project_repository()
ca_repo = repositories.get_ca_repository()
project_ca_repo = repositories.get_project_ca_repository()

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
            meta=generic_key_meta,
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
            'doesn\'t matter. headers are validated first',
            expect_errors=True,
        )
        self.assertEqual(resp.status_int, 415)


class WhenGettingOrdersListUsingOrdersResource(utils.BarbicanAPIBaseTestCase):
    def test_can_get_a_list_of_orders(self):
        # Make sure we have atleast one order to created
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(resp.status_int, 202)

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
        bogus_uuid = uuid.uuid4()
        resp = self.app.get(
            '/orders/{0}'.format(bogus_uuid),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)

    def test_delete_call_on_non_existant_order_should_give_404(self):
        bogus_uuid = uuid.uuid4()
        resp = self.app.delete(
            '/orders/{0}'.format(bogus_uuid),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)


@utils.parameterized_test_case
class WhenPuttingAnOrderWithMetadata(utils.BarbicanAPIBaseTestCase):
    def setUp(self):
        # Temporarily mock the queue until we can figure out a better way
        # TODO(jvrbanac): Remove dependence on mocks
        self.update_order_mock = mock.MagicMock()
        repositories.OrderRepo.update_order = self.update_order_mock

        super(WhenPuttingAnOrderWithMetadata, self).setUp()

    def _create_generic_order_for_put(self):
        """Create a real order to modify and perform PUT actions on

        This makes sure that a project exists for our order and that there
        is an order within the database. This is a little hacky due to issues
        testing certificate order types.
        """
        # Create generic order
        resp, order_uuid = create_order(
            self.app,
            order_type='key',
            meta=generic_key_meta
        )
        self.assertEqual(202, resp.status_int)

        # Modify the order in the DB to allow actions to be performed
        order_model = order_repo.get(order_uuid, self.project_id)
        order_model.type = 'certificate'
        order_model.status = models.States.PENDING
        order_model.meta = {'nope': 'nothing'}
        order_model.save()

        repositories.commit()

        return order_uuid

    def test_putting_on_a_order(self):
        order_uuid = self._create_generic_order_for_put()

        body = {
            'type': 'certificate',
            'meta': {'nope': 'thing'}
        }
        resp = self.app.put_json(
            '/orders/{0}'.format(order_uuid),
            body,
            headers={'Content-Type': 'application/json'}
        )

        self.assertEqual(204, resp.status_int)
        self.assertEqual(1, self.update_order_mock.call_count)

    @utils.parameterized_dataset({
        'bogus_content': ['bogus'],
        'bad_order_type': ['{"type": "secret", "meta": {}}'],
    })
    def test_return_400_on_put_with(self, body):
        order_uuid = self._create_generic_order_for_put()
        resp = self.app.put(
            '/orders/{0}'.format(order_uuid),
            body,
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_return_400_on_put_when_order_is_active(self):
        order_uuid = self._create_generic_order_for_put()

        # Put the order in a active state to prevent modification
        order_model = order_repo.get(order_uuid, self.project_id)
        order_model.status = models.States.ACTIVE
        order_model.save()
        repositories.commit()

        resp = self.app.put_json(
            '/orders/{0}'.format(order_uuid),
            {'type': 'certificate', 'meta': {}},
            headers={'Content-Type': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)


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
        self.assertEqual(order.meta, order_meta)

    def test_should_return_400_when_creating_with_empty_json(self):
        resp = self.app.post_json('/orders/', {}, expect_errors=True)
        self.assertEqual(400, resp.status_int,)

    def test_should_return_415_when_creating_with_blank_body(self):
        resp = self.app.post('/orders/', '', expect_errors=True)
        self.assertEqual(415, resp.status_int)


class WhenCreatingCertificateOrders(utils.BarbicanAPIBaseTestCase):
    def setUp(self):
        super(WhenCreatingCertificateOrders, self).setUp()
        self.certificate_meta = {
            'request': 'XXXXXX'
        }
        # Make sure we have a project
        self.project = resources.get_or_create_project(self.project_id)

        # Create CA's in the db
        self.available_ca_ids = []
        for i in range(2):
            ca_information = {
                'plugin_name': 'plugin_name',
                'plugin_ca_id': 'plugin_name ca_id1',
                'name': 'plugin name',
                'description': 'Master CA for default plugin',
                'ca_signing_certificate': 'XXXXX',
                'intermediates': 'YYYYY'
            }

            ca_model = models.CertificateAuthority(ca_information)
            ca = ca_repo.create_from(ca_model)
            self.available_ca_ids.append(ca.id)

        repositories.commit()

    def test_can_create_new_cert_order(self):
        create_resp, order_uuid = create_order(
            self.app,
            order_type='certificate',
            meta=self.certificate_meta
        )

        self.assertEqual(202, create_resp.status_int)

        order = order_repo.get(order_uuid, self.project_id)
        self.assertIsInstance(order, models.Order)

    def test_can_add_new_cert_order_with_ca_id(self):
        self.certificate_meta['ca_id'] = self.available_ca_ids[0]

        create_resp, order_uuid = create_order(
            self.app,
            order_type='certificate',
            meta=self.certificate_meta
        )

        self.assertEqual(202, create_resp.status_int)

        order = order_repo.get(order_uuid, self.project_id)
        self.assertIsInstance(order, models.Order)

    def test_can_add_new_cert_order_with_ca_id_project_ca_defined(self):
        # Create a Project CA and add it
        project_ca_model = models.ProjectCertificateAuthority(
            self.project.id,
            self.available_ca_ids[0]
        )
        project_ca_repo.create_from(project_ca_model)

        repositories.commit()

        # Attempt to create an order
        self.certificate_meta['ca_id'] = self.available_ca_ids[0]

        create_resp, order_uuid = create_order(
            self.app,
            order_type='certificate',
            meta=self.certificate_meta
        )

        self.assertEqual(202, create_resp.status_int)

        order = order_repo.get(order_uuid, self.project_id)
        self.assertIsInstance(order, models.Order)

    def test_create_w_invalid_ca_id_should_fail(self):
        self.certificate_meta['ca_id'] = 'bogus_ca_id'

        create_resp, order_uuid = create_order(
            self.app,
            order_type='certificate',
            meta=self.certificate_meta,
            expect_errors=True
        )
        self.assertEqual(400, create_resp.status_int)

    def test_create_should_fail_when_ca_not_in_defined_project_ca_ids(self):
        # Create a Project CA and add it
        project_ca_model = models.ProjectCertificateAuthority(
            self.project.id,
            self.available_ca_ids[0]
        )
        project_ca_repo.create_from(project_ca_model)

        repositories.commit()

        # Make sure we set the ca_id to an id not defined in the project
        self.certificate_meta['ca_id'] = self.available_ca_ids[1]

        create_resp, order_uuid = create_order(
            self.app,
            order_type='certificate',
            meta=self.certificate_meta,
            expect_errors=True
        )
        self.assertEqual(403, create_resp.status_int)


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
