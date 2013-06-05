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
from barbican.api import resources as res
from barbican.crypto.extension_manager import CryptoExtensionManager
from barbican.model import models
from barbican.common import config
from barbican.common import exception as excep
from barbican.common.validators import DEFAULT_MAX_SECRET_BYTES
from barbican.openstack.common import jsonutils


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingVersionResource())
    suite.addTest(WhenCreatingSecretsUsingSecretsResource())
    suite.addTest(WhenGettingSecretsListUsingSecretsResource())
    suite.addTest(WhenGettingPuttingOrDeletingSecretUsingSecretResource())
    suite.addTest(WhenCreatingOrdersUsingOrdersResource())
    suite.addText(WhenGettingOrdersListUsingOrdersResource())
    suite.addTest(WhenGettingOrDeletingOrderUsingOrderResource())

    return suite


def create_secret(mime_type, id="id", name="name",
                  algorithm=None, bit_length=None,
                  cypher_type=None, encrypted_datum=None):
    """Generate a Secret entity instance."""
    info = {'id': id,
            'name': name,
            'mime_type': mime_type,
            'algorithm': algorithm,
            'bit_length': bit_length,
            'cypher_type': cypher_type}
    secret = models.Secret(info)
    if encrypted_datum:
        secret.encrypted_data = [encrypted_datum]
    return secret


def create_order(mime_type, id="id", name="name",
                 algorithm=None, bit_length=None,
                 cypher_type=None):
    """Generate an Order entity instance."""
    order = models.Order()
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
        self.policy = MagicMock()
        self.resource = res.VersionResource(self.policy)

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
        self.plain_text = 'not-encrypted'.decode('utf-8')
        self.mime_type = 'text/plain'
        self.secret_algorithm = 'algo'
        self.secret_bit_length = 512
        self.secret_cypher_type = 'cytype'

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': self.plain_text}
        self.json = json.dumps(self.secret_req)

        self.keystone_id = 'keystone1234'
        self.tenant_entity_id = 'tid1234'
        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_entity_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = MagicMock()
        self.tenant_repo.find_by_keystone_id.return_value = self.tenant

        self.secret_repo = MagicMock()
        self.secret_repo.create_from.return_value = None

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
        self.conf = MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = CryptoExtensionManager(conf=self.conf)

        self.resource = res.SecretsResource(self.crypto_mgr,
                                            self.tenant_repo,
                                            self.secret_repo,
                                            self.tenant_secret_repo,
                                            self.datum_repo, self.policy)

    def test_should_add_new_secret(self):
        self.resource.on_post(self.req, self.resp, self.keystone_id)

        self.assertEquals(self.resp.status, falcon.HTTP_201)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertTrue(isinstance(secret, models.Secret))
        self.assertEqual(secret.name, self.name)
        self.assertEqual(secret.algorithm, self.secret_algorithm)
        self.assertEqual(secret.bit_length, self.secret_bit_length)
        self.assertEqual(secret.cypher_type, self.secret_cypher_type)
        self.assertEqual(secret.mime_type, self.mime_type)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertTrue(isinstance(tenant_secret, models.TenantSecret))
        self.assertEqual(tenant_secret.tenant_id, self.tenant_entity_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)
        self.assertEqual('cypher_text', datum.cypher_text)
        self.assertEqual(self.mime_type, datum.mime_type)
        self.assertIsNotNone(datum.kek_metadata)

    def test_should_add_new_secret_with_expiration(self):
        expiration = '2114-02-28 12:14:44.180394-05:00'
        self.secret_req.update({'expiration': expiration})
        self.stream.read.return_value = json.dumps(self.secret_req)        
        
        self.resource.on_post(self.req, self.resp, self.keystone_id)

        self.assertEquals(self.resp.status, falcon.HTTP_201)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        expected = expiration[:-6].replace('12', '17', 1)
        self.assertEqual(expected, str(secret.expiration))

    def test_should_add_new_secret_tenant_not_exist(self):
        self.tenant_repo.get.return_value = None

        self.resource.on_post(self.req, self.resp, self.keystone_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertTrue(isinstance(secret, models.Secret))
        self.assertEqual(secret.name, self.name)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertTrue(isinstance(tenant_secret, models.TenantSecret))
        self.assertEqual(self.tenant_entity_id, tenant_secret.tenant_id)
        self.assertEqual(secret.id, tenant_secret.secret_id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertTrue(isinstance(datum, models.EncryptedDatum))
        self.assertEqual('cypher_text', datum.cypher_text)
        self.assertEqual(self.mime_type, datum.mime_type)
        self.assertIsNotNone(datum.kek_metadata)

    def test_should_add_new_secret_no_plain_text(self):
        json_template = u'{{"name":"{0}", "mime_type":"{1}"}}'
        json = json_template.format(self.name, self.mime_type)
        self.stream.read.return_value = json

        self.resource.on_post(self.req, self.resp, self.keystone_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertTrue(isinstance(secret, models.Secret))
        self.assertEqual(secret.name, self.name)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertTrue(isinstance(tenant_secret, models.TenantSecret))
        self.assertEqual(tenant_secret.tenant_id, self.tenant_entity_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        self.assertFalse(self.datum_repo.create_from.called)

    def test_should_add_new_secret_plain_text_almost_too_large(self):
        big_text = ''.join(['A' for x
                            in xrange(DEFAULT_MAX_SECRET_BYTES - 10)])

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': big_text}
        self.stream.read.return_value = json.dumps(self.secret_req)

        self.resource.on_post(self.req, self.resp, self.keystone_id)

    def test_should_fail_due_to_plain_text_too_large(self):
        big_text = ''.join(['A' for x
                            in xrange(DEFAULT_MAX_SECRET_BYTES + 10)])

        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': big_text}
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_413, exception.status)

    def test_should_fail_due_to_empty_plain_text(self):
        self.secret_req = {'name': self.name,
                           'mime_type': self.mime_type,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': ''}
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_due_to_unsupported_mime(self):
        self.secret_req = {'name': self.name,
                           'mime_type': 'somethingbogushere',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'cypher_type': self.secret_cypher_type,
                           'plain_text': self.plain_text}
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenGettingSecretsListUsingSecretsResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.keystone_id = 'keystone1234'
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

        self.conf = MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = CryptoExtensionManager(conf=self.conf)

        self.req = MagicMock()
        self.req.accept = 'application/json'
        self.req._params = self.params
        self.resp = MagicMock()
        self.resource = res.SecretsResource(self.crypto_mgr, self.tenant_repo,
                                            self.secret_repo,
                                            self.tenant_secret_repo,
                                            self.datum_repo, self.policy)

    def test_should_get_list_secrets(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.params.get('offset',
                                                                self.offset),
                                     limit_arg=self.params.get('limit',
                                                               self.limit),
                                     suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('previous' in resp_body)
        self.assertTrue('next' in resp_body)

        url_nav_next = self._create_url(self.keystone_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.keystone_id,
                                        0, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.keystone_id)
        self.assertTrue(self.resp.body.count(url_hrefs) ==
                        (self.num_secrets + 2))

    def test_should_handle_no_secrets(self):

        del self.secrets[:]

        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.params.get('offset',
                                                                self.offset),
                                     limit_arg=self.params.get('limit',
                                                               self.limit),
                                     suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertFalse('previous' in resp_body)
        self.assertFalse('next' in resp_body)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/v1/{0}/secrets?limit={1}&offset={2}'.format(keystone_id,
                                                                 limit,
                                                                 offset)
        else:
            return '/v1/{0}/secrets'.format(keystone_id)


class WhenGettingPuttingOrDeletingSecretUsingSecretResource(
        unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenantid1234'
        self.keystone_id = 'keystone1234'
        self.name = 'name1234'
        self.mime_type = 'text/plain'
        secret_id = "idsecret1"
        datum_id = "iddatum1"
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"

        self.datum = models.EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.mime_type = self.mime_type
        self.datum.cypher_text = "cypher_text"
        self.datum.kek_metadata = "kekedata"

        self.secret = create_secret(self.mime_type,
                                    id=secret_id,
                                    name=self.name,
                                    algorithm=self.secret_algorithm,
                                    bit_length=self.secret_bit_length,
                                    cypher_type=self.secret_cypher_type,
                                    encrypted_datum=self.datum)

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_id
        self.keystone_id = self.keystone_id
        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.secret_repo = MagicMock()
        self.secret_repo.get.return_value = self.secret
        self.secret_repo.delete_entity_by_id.return_value = None

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.req.accept = 'application/json'
        self.resp = MagicMock()

        self.conf = MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = CryptoExtensionManager(conf=self.conf)

        self.policy = MagicMock()
        self.resource = res.SecretResource(self.crypto_mgr,
                                           self.tenant_repo,
                                           self.secret_repo,
                                           self.tenant_secret_repo,
                                           self.datum_repo, self.policy)

    def test_should_get_secret_as_json(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.secret_repo\
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('content_types' in resp_body)
        self.assertTrue(self.datum.mime_type in
                        resp_body['content_types'].itervalues())

    def test_should_get_secret_as_plain(self):
        self.req.accept = 'text/plain'

        self.resource.on_get(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = self.resp.body
        self.assertIsNotNone(resp_body)

    def test_should_throw_exception_for_get_when_secret_not_found(self):
        self.secret_repo.get.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def test_should_throw_exception_for_get_when_accept_not_supported(self):

        self.req.accept = 'bogusaccept'

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_406, exception.status)

    def test_should_throw_exception_for_get_when_datum_not_available(self):

        self.req.accept = 'text/plain'
        self.secret.encrypted_data = []

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def test_should_put_secret_as_plain(self):
        self._setup_for_puts()

        self.resource.on_put(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertTrue(isinstance(datum, models.EncryptedDatum))
        self.assertEqual('cypher_text', datum.cypher_text)
        self.assertEqual(self.mime_type, datum.mime_type)
        self.assertIsNotNone(datum.kek_metadata)

    def test_should_fail_put_secret_as_json(self):
        self._setup_for_puts()

        # Force error, as content_type of PUT doesn't match
        #   the secret's mime-type.
        self.req.content_type = 'application/json'

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_415, exception.status)

    def test_should_fail_put_secret_not_found(self):
        self._setup_for_puts()

        # Force error, due to secret not found.
        self.secret_repo.get.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def test_should_fail_put_secret_no_plain_text(self):
        self._setup_for_puts()

        # Force error due to no data passed in the request.
        self.stream.read.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_put_secret_with_existing_datum(self):
        self._setup_for_puts()

        # Force error due to secret already having data
        self.secret.encrypted_data = [self.datum]

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_409, exception.status)

    def test_should_fail_due_to_empty_plain_text(self):
        self._setup_for_puts()

        self.stream.read.return_value = ''

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_due_to_plain_text_too_large(self):
        self._setup_for_puts()

        big_text = ''.join(['A' for x in xrange(2 * DEFAULT_MAX_SECRET_BYTES)])
        self.stream.read.return_value = big_text

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_413, exception.status)

    def test_should_delete_secret(self):
        self.resource.on_delete(self.req, self.resp, self.keystone_id,
                                self.secret.id)

        self.secret_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.secret.id,
                                     keystone_id=self.keystone_id)

    def test_should_throw_exception_for_delete_when_secret_not_found(self):
        self.secret_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_delete(self.req, self.resp, self.keystone_id,
                                    self.secret.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

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
        self.secret_mime_type = 'text/plain'
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_cypher_type = "cytype"

        self.tenant_internal_id = 'tenantid1234'
        self.tenant_keystone_id = 'keystoneid1234'

        self.tenant = models.Tenant()
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
        self.policy = MagicMock()
        self.resource = res.OrdersResource(self.tenant_repo, self.order_repo,
                                           self.queue_resource, self.policy)

    def test_should_add_new_order(self):
        self.resource.on_post(self.req, self.resp, self.tenant_keystone_id)

        self.queue_resource.process_order \
            .assert_called_once_with(order_id=None,
                                     keystone_id=self.tenant_keystone_id)

        args, kwargs = self.order_repo.create_from.call_args
        order = args[0]
        self.assertTrue(isinstance(order, models.Order))

    def test_should_fail_add_new_order_no_secret(self):
        self.stream.read.return_value = '{}'

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp,
                                  self.tenant_keystone_id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_add_new_order_bad_json(self):
        self.stream.read.return_value = ''

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp,
                                  self.tenant_keystone_id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenGettingOrdersListUsingOrdersResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.keystone_id = 'keystoneid1234'
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
        self.resource = res.OrdersResource(self.tenant_repo, self.order_repo,
                                           self.queue_resource, self.policy)

    def test_should_get_list_orders(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.order_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.params.get('offset',
                                                                self.offset),
                                     limit_arg=self.params.get('limit',
                                                               self.limit),
                                     suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertTrue('previous' in resp_body)
        self.assertTrue('next' in resp_body)

        url_nav_next = self._create_url(self.keystone_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.keystone_id,
                                        0, self.limit)
        self.assertTrue(self.resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.keystone_id)
        self.assertTrue(self.resp.body.count(url_hrefs) ==
                        (self.num_orders + 2))

    def test_should_handle_no_orders(self):

        del self.orders[:]

        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.order_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.params.get('offset',
                                                                self.offset),
                                     limit_arg=self.params.get('limit',
                                                               self.limit),
                                     suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertFalse('previous' in resp_body)
        self.assertFalse('next' in resp_body)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/v1/{0}/orders?limit={1}&offset={2}'.format(keystone_id,
                                                                limit,
                                                                offset)
        else:
            return '/v1/{0}/orders'.format(self.keystone_id)


class WhenGettingOrDeletingOrderUsingOrderResource(unittest.TestCase):

    def setUp(self):
        self.tenant_keystone_id = 'keystoneid1234'
        self.requestor = 'requestor1234'

        self.order = create_order(id="id1", name="name",
                                  mime_type="name")

        self.order_repo = MagicMock()
        self.order_repo.get.return_value = self.order
        self.order_repo.delete_entity_by_id.return_value = None

        self.policy = MagicMock()

        self.req = MagicMock()
        self.resp = MagicMock()

        self.policy = MagicMock()

        self.resource = res.OrderResource(self.order_repo, self.policy)

    def test_should_get_order(self):
        self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                             self.order.id)

        self.order_repo.get \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.tenant_keystone_id,
                                     suppress_exception=True)

    def test_should_delete_order(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_keystone_id,
                                self.order.id)

        self.order_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.tenant_keystone_id)

    def test_should_throw_exception_for_get_when_order_not_found(self):
        self.order_repo.get.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                                 self.order.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def test_should_throw_exception_for_delete_when_order_not_found(self):
        self.order_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_delete(self.req, self.resp,
                                    self.tenant_keystone_id,
                                    self.order.id)

        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)


if __name__ == '__main__':
    unittest.main()
