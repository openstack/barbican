# Copyright (c) 2013 Rackspace, Inc.
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

from mock import MagicMock
import falcon
import json
import unittest

from datetime import datetime
from barbican.api.resources import (VersionResource,
                                    SecretsResource, SecretResource,
                                    OrdersResource, OrderResource)
from barbican.model.models import (Secret, Tenant, TenantSecret,
                                   Order, EncryptedDatum)
from barbican.crypto.fields import decrypt_value, encrypt_value
from barbican.common import config
from barbican.common import exception
from barbican.openstack.common import jsonutils


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingVersionResource())
    suite.addTest(WhenCreatingSecretsUsingSecretsResource())
    suite.addTest(WhenGettingOrDeletingSecretUsingSecretResource())
    suite.addTest(WhenCreatingOrdersUsingOrdersResource())
    suite.addTest(WhenGettingOrDeletingOrderUsingOrderResource())

    return suite


def create_secret(mime_type, id = "id", name = "name",
                  algorithm = None, bit_length = None,
                  cypher_type = None, encrypted_datum = None):
    """Generate a Secret entity instance."""
    secret = Secret()
    secret.id = id
    secret.name = name
    secret.mime_type = mime_type
    secret.algorithm = algorithm
    secret.bit_length = bit_length
    secret.cypher_type = cypher_type
    if encrypted_datum:
        secret.encrypted_data = [encrypted_datum]
    return secret


def create_order(mime_type, id = "id", name = "name",
                  algorithm = None, bit_length = None,
                  cypher_type = None):
    """Generate an Order entity instance."""
    order = Order()
    order.id = id
    order.secret_name = name
    order.secret_mime_type = mime_type
    order.secret_algorithm = algorithm
    order.secret_bit_length = bit_length
    order.secret_cypher_type = cypher_type
    return order


class WhenTestingVersionResource(unittest.TestCase):

    def setUp(self):
        self.policy = MagicMock()

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = VersionResource(self.policy)

    def test_should_return_200_on_get(self):
        self.resource.on_get(self.req, self.resp)
        self.assertEqual(falcon.HTTP_200, self.resp.status)

    def test_should_return_version_json(self):
        self.resource.on_get(self.req, self.resp)

        parsed_body = json.loads(self.resp.body)

        self.assertTrue('v1' in parsed_body)
        self.assertEqual('current', parsed_body['v1'])


class WhenCreatingSecretsUsingSecretsResource(unittest.TestCase):

    def setUp(self):
        self.name = 'name'
        self.plain_text = 'not-encrypted'
        self.mime_type = 'text/plain'
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': self.plain_text}
        self.json = json.dumps(self.secret_req)

        self.keystone_id = 'keystone1234'
        self.tenant_id = 'tenantid1234'
        self.tenant = Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.secret_repo = MagicMock()
        self.secret_repo.create_from.return_value = None
        self.secret_repo.find_by_name.return_value = None

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.policy = MagicMock()

        self.stream = MagicMock()
        self.stream.read.return_value = self.json

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = SecretsResource(self.tenant_repo, self.secret_repo,
                                        self.tenant_secret_repo,
                                        self.datum_repo, self.policy)

    def test_should_add_new_secret(self):
        self.resource.on_post(self.req, self.resp, self.tenant_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        assert isinstance(secret, Secret)
        assert secret.name == self.name
        assert secret.algorithm == self.secret_algorithm
        assert secret.bit_length == self.secret_bit_length
        assert secret.cypher_type == self.secret_cypher_type
        assert secret.mime_type == self.mime_type

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        assert isinstance(tenant_secret, TenantSecret)
        assert tenant_secret.tenant_id == self.tenant_id
        assert tenant_secret.secret_id == secret.id

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        assert isinstance(datum, EncryptedDatum)
        assert encrypt_value(self.plain_text) == datum.cypher_text
        assert self.mime_type == datum.mime_type
        assert datum.kek_metadata is not None

    def test_should_add_new_secret_tenant_not_exist(self):
        self.tenant_repo.get.return_value = None

        self.resource.on_post(self.req, self.resp, self.tenant_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        assert isinstance(secret, Secret)
        assert secret.name == self.name

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        assert isinstance(tenant_secret, TenantSecret)
        assert not tenant_secret.tenant_id
        assert tenant_secret.secret_id == secret.id

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        assert isinstance(datum, EncryptedDatum)
        assert encrypt_value(self.plain_text) == datum.cypher_text
        assert self.mime_type == datum.mime_type
        assert datum.kek_metadata is not None

    def test_should_add_new_secret_no_plain_text(self):
        json_template = u'{{"name":"{0}", "mime_type":"{1}"}}'
        json = json_template.format(self.name, self.mime_type)
        self.stream.read.return_value = json

        self.resource.on_post(self.req, self.resp, self.tenant_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        assert isinstance(secret, Secret)
        assert secret.name == self.name

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        assert isinstance(tenant_secret, TenantSecret)
        assert tenant_secret.tenant_id == self.tenant_id
        assert tenant_secret.secret_id == secret.id

        assert not self.datum_repo.create_from.called


class WhenGettingSecretsListUsingSecretsResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.name = 'name1234'
        self.mime_type = 'text/plain'
        secret_id_base = "idsecret"
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"
        self.params = {'offset': 2, 'limit': 2}

        self.num_secrets = 10
        self.offset = 2
        self.limit = 2

        secret_params = {'mime_type': self.mime_type,
                         'name': self.name,
                         'algorithm': self.secret_algorithm,
                         'bit_length': self.secret_bit_length,
                         'cypher_type': self.secret_cypher_type,
                         'encrypted_datum': None}

        self.secrets = [create_secret(id='id' + str(id), **secret_params) for
                        id in xrange(self.num_secrets)]

        self.secret_repo = MagicMock()
        self.secret_repo.get_by_create_date.return_value = (self.secrets,
                                                            self.offset,
                                                            self.limit)

        self.tenant_repo = MagicMock()

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.req.accept = 'application/json'
        self.req._params = self.params
        self.resp = MagicMock()
        self.resource = SecretsResource(self.tenant_repo, self.secret_repo,
                                        self.tenant_secret_repo,
                                        self.datum_repo, self.policy)

    def test_should_get_list_secrets(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id)

        self.secret_repo.get_by_create_date.assert_called_once_with(
                                    offset_arg=self.params.get('offset',
                                                               self.offset),
                                    limit_arg=self.params.get('limit',
                                                              self.limit),
                                    suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('previous' in resp_body)
        self.assertTrue('next' in resp_body)

        url_nav_next = self._create_url(self.tenant_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.tenant_id,
                                        0, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.tenant_id)
        self.assertTrue(self.resp.body.count(url_hrefs) ==
                        (self.num_secrets + 2))

    def test_should_fail_no_secrets(self):

        del self.secrets[:]

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.tenant_id)

        exception = cm.exception
        assert falcon.HTTP_400 == exception.status

    def _create_url(self, tenant_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/v1/{0}/secrets?limit={1}&offset={2}'.format(
                            tenant_id,
                            limit,
                            offset)
        else:
            return '/v1/{0}/secrets'.format(self.tenant_id)


class WhenGettingPuttingOrDeletingSecretUsingSecretResource(
    unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.name = 'name1234'
        self.mime_type = 'text/plain'
        secret_id = "idsecret1"
        datum_id = "iddatum1"
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"

        self.datum = EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.mime_type = self.mime_type
        self.datum.cypher_text = "cypher_text"
        self.datum.kek_metadata = "kekedata"

        self.secret = create_secret(self.mime_type, id = secret_id,
                                    name = self.name,
                                    algorithm = self.secret_algorithm,
                                    bit_length = self.secret_bit_length,
                                    cypher_type = self.secret_cypher_type,
                                    encrypted_datum = self.datum)

        self.secret_repo = MagicMock()
        self.secret_repo.get.return_value = self.secret
        self.secret_repo.delete_entity.return_value = None

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.req.accept = 'application/json'
        self.resp = MagicMock()
        self.resource = SecretResource(self.secret_repo,
                                       self.tenant_secret_repo,
                                       self.datum_repo, self.policy)

    def test_should_get_secret_as_json(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id,
                             self.secret.id)

        self.secret_repo.get.assert_called_once_with(entity_id=self.secret.id,
                                                     suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('content_types' in resp_body)
        self.assertTrue(self.datum.mime_type in
                        resp_body['content_types'].itervalues())

    def test_should_get_secret_as_plain(self):
        self.req.accept = 'text/plain'

        self.resource.on_get(self.req, self.resp, self.tenant_id,
                             self.secret.id)

        self.secret_repo.get.assert_called_once_with(entity_id=self.secret.id,
                                                     suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = self.resp.body
        assert resp_body

    def test_should_put_secret_as_plain(self):
        self._setup_for_puts()

        self.resource.on_put(self.req, self.resp, self.tenant_id,
                             self.secret.id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        assert isinstance(datum, EncryptedDatum)
        assert encrypt_value(self.plain_text) == datum.cypher_text
        assert self.mime_type == datum.mime_type
        assert datum.kek_metadata is not None

    def test_should_fail_put_secret_as_json(self):
        self._setup_for_puts()

        # Force error, as content_type of PUT doesn't match
        #   the secret's mime-type.
        self.req.content_type = 'application/json'

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

        exception = cm.exception
        assert falcon.HTTP_415 == exception.status

    def test_should_fail_put_secret_not_found(self):
        self._setup_for_puts()

        # Force error, due to secret not found.
        self.secret_repo.get.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

        exception = cm.exception
        assert falcon.HTTP_400 == exception.status

    def test_should_fail_put_secret_no_plain_text(self):
        self._setup_for_puts()

        # Force error due to no data passed in the request.
        self.stream.read.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

        exception = cm.exception
        assert falcon.HTTP_400 == exception.status

    def test_should_fail_put_secret_with_existing_datum(self):
        self._setup_for_puts()

        # Force error due to secret already having data
        self.secret.encrypted_data = [self.datum]

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

        exception = cm.exception
        assert falcon.HTTP_409 == exception.status

    def test_should_delete_secret(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                self.secret.id)

        self.secret_repo.get.assert_called_once_with(entity_id=self.secret.id)
        self.secret_repo.delete_entity.assert_called_once_with(self.secret)

    def test_should_throw_exception_for_get_when_secret_not_found(self):
        self.secret_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

    def test_should_throw_exception_for_delete_when_secret_not_found(self):
        self.secret_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                    self.secret.id)

    def _setup_for_puts(self):
        self.plain_text = "plain_text"
        self.req.accept = self.mime_type
        self.req.content_type = self.mime_type

        self.secret.encrypted_data = []

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.stream = MagicMock()
        self.stream.read.return_value = self.plain_text
        self.req.stream = self.stream


class WhenCreatingOrdersUsingOrdersResource(unittest.TestCase):

    def setUp(self):
        self.secret_name = 'name'
        self.secret_mime_type = 'type'
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"

        self.tenant_internal_id = 'tenantid1234'
        self.tenant_keystone_id = 'keystoneid1234'

        self.tenant = Tenant()
        self.tenant.id = self.tenant_internal_id
        self.tenant.keystone_id = self.tenant_keystone_id

        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.order_repo = MagicMock()
        self.order_repo.create_from.return_value = None

        self.queue_resource = MagicMock()
        self.queue_resource.process_order.return_value = None

        self.policy = MagicMock()

        self.stream = MagicMock()

        order_req = {'secret': {'name': self.secret_name,
                                'mime_type': self.secret_mime_type,
                                'algorithm': self.secret_algorithm,
                                'bit_length': self.secret_bit_length,
                                'cypher_type': self.secret_cypher_type}}
        self.json = json.dumps(order_req)
        self.stream.read.return_value = self.json

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = OrdersResource(self.tenant_repo, self.order_repo,
                                       self.queue_resource, self.policy)

    def test_should_add_new_order(self):
        self.resource.on_post(self.req, self.resp, self.tenant_keystone_id)

        self.queue_resource.process_order.assert_called_once_with(order_id=
                                                                  None)

        args, kwargs = self.order_repo.create_from.call_args
        assert isinstance(args[0], Order)


class WhenGettingOrdersListUsingOrdersResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.name = 'name1234'
        self.mime_type = 'text/plain'
        secret_id_base = "idsecret"
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"
        self.params = {'offset': 2, 'limit': 2}

        self.num_orders = 10
        self.offset = 2
        self.limit = 2

        order_params = {'mime_type': self.mime_type,
                        'name': self.name,
                        'algorithm': self.secret_algorithm,
                        'bit_length': self.secret_bit_length,
                        'cypher_type': self.secret_cypher_type}

        self.orders = [create_order(id='id' + str(id), **order_params) for
                       id in xrange(self.num_orders)]

        self.order_repo = MagicMock()
        self.order_repo.get_by_create_date.return_value = (self.orders,
                                                           self.offset,
                                                           self.limit)

        self.tenant_repo = MagicMock()

        self.queue_resource = MagicMock()
        self.queue_resource.process_order.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.req.accept = 'application/json'
        self.req._params = self.params
        self.resp = MagicMock()
        self.resource = OrdersResource(self.tenant_repo, self.order_repo,
                                       self.queue_resource, self.policy)

    def test_should_get_list_orders(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id)

        self.order_repo.get_by_create_date.assert_called_once_with(
                                    offset_arg=self.params.get('offset',
                                                               self.offset),
                                    limit_arg=self.params.get('limit',
                                                              self.limit),
                                    suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('previous' in resp_body)
        self.assertTrue('next' in resp_body)

        url_nav_next = self._create_url(self.tenant_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.tenant_id,
                                        0, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.tenant_id)
        self.assertTrue(self.resp.body.count(url_hrefs) ==
                        (self.num_orders + 2))

    def test_should_fail_no_orders(self):

        del self.orders[:]

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.tenant_id)

        exception = cm.exception
        assert falcon.HTTP_400 == exception.status

    def _create_url(self, tenant_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/v1/{0}/orders?limit={1}&offset={2}'.format(
                            tenant_id,
                            limit,
                            offset)
        else:
            return '/v1/{0}/orders'.format(self.tenant_id)


class WhenGettingOrDeletingOrderUsingOrderResource(unittest.TestCase):

    def setUp(self):
        self.tenant_keystone_id = 'keystoneid1234'
        self.requestor = 'requestor1234'

        self.order = create_order(id = "id1", name = "name",
                                  mime_type = "name")

        self.order_repo = MagicMock()
        self.order_repo.get.return_value = self.order
        self.order_repo.delete_entity.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = OrderResource(self.order_repo, self.policy)

    def test_should_get_order(self):
        self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                             self.order.id)

        self.order_repo.get.assert_called_once_with(entity_id=self.order.id,
                                                    suppress_exception=True)

    def test_should_delete_order(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_keystone_id,
                                self.order.id)

        self.order_repo.get.assert_called_once_with(entity_id=self.order.id)
        self.order_repo.delete_entity.assert_called_once_with(self.order)

    def test_should_throw_exception_for_get_when_order_not_found(self):
        self.order_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                                 self.order.id)

    def test_should_throw_exception_for_delete_when_order_not_found(self):
        self.order_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp,
                                    self.tenant_keystone_id,
                                    self.order.id)


if __name__ == '__main__':
    unittest.main()
