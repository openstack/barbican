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

"""
This test module focuses on typical-flow business logic tests with the API
resource classes. For RBAC tests of these classes, see the
'resources_policy_test.py' module.
"""

import base64
import json
import unittest
import urllib

import falcon
import mock

from barbican.api import resources as res
from barbican.common import exception as excep
from barbican.common import utils
from barbican.common import validators
from barbican.crypto import extension_manager as em
from barbican.model import models
from barbican.openstack.common import jsonutils
from barbican.tests.crypto import test_plugin as ctp


def create_secret(id_ref="id", name="name",
                  algorithm=None, bit_length=None,
                  mode=None, encrypted_datum=None):
    """Generate a Secret entity instance."""
    info = {'id': id_ref,
            'name': name,
            'algorithm': algorithm,
            'bit_length': bit_length,
            'mode': mode}
    secret = models.Secret(info)
    if encrypted_datum:
        secret.encrypted_data = [encrypted_datum]
    return secret


def create_order(id_ref="id",
                 name="name",
                 algorithm=None,
                 bit_length=None,
                 mode=None):
    """Generate an Order entity instance."""
    order = models.Order()
    order.id = id_ref
    order.secret_name = name
    order.secret_algorithm = algorithm
    order.secret_bit_length = bit_length
    order.secret_mode = mode
    return order


def validate_datum(test, datum):
    test.assertIsNone(datum.kek_meta_extended)
    test.assertIsNotNone(datum.kek_meta_tenant)
    test.assertTrue(datum.kek_meta_tenant.bind_completed)
    test.assertIsNotNone(datum.kek_meta_tenant.plugin_name)
    test.assertIsNotNone(datum.kek_meta_tenant.kek_label)


def create_verification(id_ref="id"):
    """Generate an Verification entity instance."""
    verify = models.Verification()
    verify.id = id_ref
    verify.resource_type = 'image'
    verify.resource_action = 'vm_attach'
    verify.resource_ref = 'http://www.myres.com'
    verify.impersonation_allowed = True
    return verify


class WhenTestingVersionResource(unittest.TestCase):
    def setUp(self):
        self.req = mock.MagicMock()
        self.resp = mock.MagicMock()
        self.resource = res.VersionResource()

    def test_should_return_200_on_get(self):
        self.resource.on_get(self.req, self.resp)
        self.assertEqual(falcon.HTTP_200, self.resp.status)

    def test_should_return_version_json(self):
        self.resource.on_get(self.req, self.resp)

        parsed_body = json.loads(self.resp.body)

        self.assertTrue('v1' in parsed_body)
        self.assertEqual('current', parsed_body['v1'])


class BaseSecretsResource(unittest.TestCase):
    """Base test class for the Secrets resource."""
    def setUp(self):
        pass

    def _init(self, payload=b'not-encrypted',
              payload_content_type='text/plain',
              payload_content_encoding=None):
        self.name = 'name'
        self.payload = payload
        self.payload_content_type = payload_content_type
        self.payload_content_encoding = payload_content_encoding
        self.secret_algorithm = 'AES'
        self.secret_bit_length = 256
        self.secret_mode = 'CBC'
        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode}
        if payload:
            self.secret_req['payload'] = payload
        if payload_content_type:
            self.secret_req['payload_content_type'] = payload_content_type
        if payload_content_encoding:
            self.secret_req['payload_content_encoding'] = \
                payload_content_encoding
        self.json = json.dumps(self.secret_req)

        self.keystone_id = 'keystone1234'
        self.tenant_entity_id = 'tid1234'
        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_entity_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.find_by_keystone_id.return_value = self.tenant

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None

        self.tenant_secret_repo = mock.MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_datum = models.KEKDatum()
        self.kek_datum.plugin_name = utils.generate_fullname_for(
            ctp.TestCryptoPlugin())
        self.kek_datum.kek_label = "kek_label"
        self.kek_datum.bind_completed = False
        self.kek_repo = mock.MagicMock()
        self.kek_repo.find_or_create_kek_metadata.return_value = self.kek_datum

        self.stream = mock.MagicMock()
        self.stream.read.return_value = self.json

        self.req = mock.MagicMock()
        self.req.stream = self.stream

        self.resp = mock.MagicMock()
        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

        self.resource = res.SecretsResource(self.crypto_mgr,
                                            self.tenant_repo,
                                            self.secret_repo,
                                            self.tenant_secret_repo,
                                            self.datum_repo,
                                            self.kek_repo)

    def _test_should_add_new_secret_with_expiration(self):
        expiration = '2114-02-28 12:14:44.180394-05:00'
        self.secret_req.update({'expiration': expiration})
        self.stream.read.return_value = json.dumps(self.secret_req)

        self.resource.on_post(self.req, self.resp, self.keystone_id)

        self.assertEquals(self.resp.status, falcon.HTTP_201)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        expected = expiration[:-6].replace('12', '17', 1)
        self.assertEqual(expected, str(secret.expiration))

    def _test_should_add_new_secret_one_step(self, check_tenant_id=True):
        """Test the one-step secret creation.

        :param check_tenant_id: True if the retrieved Tenant id needs to be
        verified, False to skip this check (necessary for new-Tenant flows).
        """
        self.resource.on_post(self.req, self.resp, self.keystone_id)

        self.assertEquals(self.resp.status, falcon.HTTP_201)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertIsInstance(secret, models.Secret)
        self.assertEqual(secret.name, self.name)
        self.assertEqual(secret.algorithm, self.secret_algorithm)
        self.assertEqual(secret.bit_length, self.secret_bit_length)
        self.assertEqual(secret.mode, self.secret_mode)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertIsInstance(tenant_secret, models.TenantSecret)
        if check_tenant_id:
            self.assertEqual(tenant_secret.tenant_id, self.tenant_entity_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)
        self.assertEqual(base64.b64encode('cypher_text'), datum.cypher_text)
        self.assertEqual(self.payload_content_type, datum.content_type)

        validate_datum(self, datum)

    def _test_should_add_new_secret_if_tenant_does_not_exist(self):
        self.tenant_repo.get.return_value = None
        self.tenant_repo.find_by_keystone_id.return_value = None

        self._test_should_add_new_secret_one_step(check_tenant_id=False)

        args, kwargs = self.tenant_repo.create_from.call_args
        tenant = args[0]
        self.assertIsInstance(tenant, models.Tenant)
        self.assertEqual(self.keystone_id, tenant.keystone_id)

    def _test_should_add_new_secret_metadata_without_payload(self):
        self.stream.read.return_value = json.dumps({'name': self.name})

        self.resource.on_post(self.req, self.resp, self.keystone_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertIsInstance(secret, models.Secret)
        self.assertEqual(secret.name, self.name)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertIsInstance(tenant_secret, models.TenantSecret)
        self.assertEqual(tenant_secret.tenant_id, self.tenant_entity_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        self.assertFalse(self.datum_repo.create_from.called)

    def _test_should_add_new_secret_payload_almost_too_large(self):
        if validators.DEFAULT_MAX_SECRET_BYTES % 4:
            raise ValueError('Tests currently require max secrets divides by '
                             '4 evenly, due to base64 encoding.')

        big_text = ''.join(['A' for x
                            in xrange(validators.DEFAULT_MAX_SECRET_BYTES -
                                      8)])

        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': big_text,
                           'payload_content_type': self.payload_content_type}
        if self.payload_content_encoding:
            self.secret_req['payload_content_encoding'] = \
                self.payload_content_encoding
        self.stream.read.return_value = json.dumps(self.secret_req)

        self.resource.on_post(self.req, self.resp, self.keystone_id)

    def _test_should_fail_due_to_payload_too_large(self):
        big_text = ''.join(['A' for x
                            in xrange(validators.DEFAULT_MAX_SECRET_BYTES +
                                      10)])

        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': big_text,
                           'payload_content_type': self.payload_content_type}
        if self.payload_content_encoding:
            self.secret_req['payload_content_encoding'] = \
                self.payload_content_encoding
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_413, exception.status)

    def _test_should_fail_due_to_empty_payload(self):
        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': ''}
        if self.payload_content_type:
            self.secret_req['payload_content_type'] = self.payload_content_type
        if self.payload_content_encoding:
            self.secret_req['payload_content_encoding'] = \
                self.payload_content_encoding
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenCreatingPlainTextSecretsUsingSecretsResource(BaseSecretsResource):
    def setUp(self):
        super(WhenCreatingPlainTextSecretsUsingSecretsResource, self).setUp()
        self._init()  # Default settings setup a plain-text secret.

    def test_should_add_new_secret_one_step(self):
        self._test_should_add_new_secret_one_step()

    def test_should_add_new_secret_with_expiration(self):
        self._test_should_add_new_secret_with_expiration()

    def test_should_add_new_secret_if_tenant_does_not_exist(self):
        self._test_should_add_new_secret_if_tenant_does_not_exist()

    def test_should_add_new_secret_metadata_without_payload(self):
        self._test_should_add_new_secret_metadata_without_payload()

    def test_should_add_new_secret_payload_almost_too_large(self):
        self._test_should_add_new_secret_payload_almost_too_large()

    def test_should_fail_due_to_payload_too_large(self):
        self._test_should_fail_due_to_payload_too_large()

    def test_should_fail_due_to_empty_payload(self):
        self._test_should_fail_due_to_empty_payload()

    def test_should_fail_due_to_unsupported_payload_content_type(self):
        self.secret_req = {'name': self.name,
                           'payload_content_type': 'somethingbogushere',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': self.payload}
        self.stream.read.return_value = json.dumps(self.secret_req)

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenCreatingBinarySecretsUsingSecretsResource(BaseSecretsResource):
    def setUp(self):
        super(WhenCreatingBinarySecretsUsingSecretsResource, self).setUp()
        self._init(payload="...lOtfqHaUUpe6NqLABgquYQ==",
                   payload_content_type='application/octet-stream',
                   payload_content_encoding='base64')

    def test_should_add_new_secret_one_step(self):
        self._test_should_add_new_secret_one_step()

    def test_should_add_new_secret_with_expiration(self):
        self._test_should_add_new_secret_with_expiration()

    def test_should_add_new_secret_if_tenant_does_not_exist(self):
        self._test_should_add_new_secret_if_tenant_does_not_exist()

    def test_should_add_new_secret_metadata_without_payload(self):
        self._test_should_add_new_secret_metadata_without_payload()

    def test_should_add_new_secret_payload_almost_too_large(self):
        self._test_should_add_new_secret_payload_almost_too_large()

    def test_should_fail_due_to_payload_too_large(self):
        self._test_should_fail_due_to_payload_too_large()

    def test_should_fail_due_to_empty_payload(self):
        self._test_should_fail_due_to_empty_payload()

    def test_create_secret_fails_with_binary_payload_no_encoding(self):
        self.stream.read.return_value = json.dumps(
            {'name': self.name,
             'algorithm': self.secret_algorithm,
             'bit_length': self.secret_bit_length,
             'mode': self.secret_mode,
             'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
             'payload_content_type': 'application/octet-stream'}
        )

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_create_secret_fails_with_binary_payload_bad_encoding(self):
        self.stream.read.return_value = json.dumps(
            {'name': self.name,
             'algorithm': self.secret_algorithm,
             'bit_length': self.secret_bit_length,
             'mode': self.secret_mode,
             'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
             'payload_content_type': 'application/octet-stream',
             'payload_content_encoding': 'bogus64'}
        )

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_create_secret_fails_with_binary_payload_no_content_type(self):
        self.stream.read.return_value = json.dumps(
            {'name': self.name,
             'algorithm': self.secret_algorithm,
             'bit_length': self.secret_bit_length,
             'mode': self.secret_mode,
             'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
             'payload_content_encoding': 'base64'}
        )

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_create_secret_fails_with_bad_payload(self):
        self.stream.read.return_value = json.dumps(
            {'name': self.name,
             'algorithm': self.secret_algorithm,
             'bit_length': self.secret_bit_length,
             'mode': self.secret_mode,
             'payload': 'AAAAAAAAA',
             'payload_content_type': 'application/octet-stream',
             'payload_content_encoding': 'base64'}
        )

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp, self.keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenGettingSecretsListUsingSecretsResource(unittest.TestCase):
    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.keystone_id = 'keystone1234'
        self.name = 'name 1234 !@#$%^&*()_+=-{}[];:<>,./?'
        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"

        self.num_secrets = 10
        self.offset = 2
        self.limit = 2

        secret_params = {'name': self.name,
                         'algorithm': self.secret_algorithm,
                         'bit_length': self.secret_bit_length,
                         'mode': self.secret_mode,
                         'encrypted_datum': None}

        self.secrets = [create_secret(id_ref='id' + str(id),
                                      **secret_params) for
                        id in xrange(self.num_secrets)]
        self.total = len(self.secrets)

        self.secret_repo = mock.MagicMock()
        self.secret_repo.get_by_create_date.return_value = (self.secrets,
                                                            self.offset,
                                                            self.limit,
                                                            self.total)

        self.tenant_repo = mock.MagicMock()

        self.tenant_secret_repo = mock.MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

        self.req = mock.MagicMock()
        self.req.accept = 'application/json'
        self.req.get_param = mock.Mock()
        self.params = {'offset': self.offset,
                       'limit': self.limit,
                       'name': None,
                       'alg': None,
                       'bits': 0,
                       'mode': None}
        self.req.get_param.side_effect = self.params.get

        self.resp = mock.MagicMock()
        self.resource = res.SecretsResource(self.crypto_mgr, self.tenant_repo,
                                            self.secret_repo,
                                            self.tenant_secret_repo,
                                            self.datum_repo,
                                            self.kek_repo)

    def test_should_list_secrets_by_name(self):
        # Quote the name parameter to simulate how it would be
        # received in practice via a REST-ful GET query.
        self.params['name'] = urllib.quote_plus(self.name)

        self.resource.on_get(self.req, self.resp, self.keystone_id)

        # Verify that the name is unquoted correctly in the
        # secrets.on_get function prior to searching the repo.
        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
                                     suppress_exception=True,
                                     name=self.name,
                                     alg=None, mode=None,
                                     bits=0)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertIn('secrets', resp_body)
        secrets = resp_body['secrets']
        # The result should be the unquoted name
        self.assertEqual(secrets[0]['name'], self.name)

    def test_should_get_list_secrets(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
                                     suppress_exception=True,
                                     name=None, alg=None, mode=None,
                                     bits=0)

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

    def test_response_should_include_total(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)
        resp_body = jsonutils.loads(self.resp.body)
        self.assertIn('total', resp_body)
        self.assertEqual(resp_body['total'], self.total)

    def test_should_handle_no_secrets(self):

        del self.secrets[:]

        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
                                     suppress_exception=True,
                                     name=None, alg=None, mode=None,
                                     bits=0)

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


class WhenGettingPuttingOrDeletingSecretUsingSecretResource(unittest.TestCase):
    def setUp(self):
        self.tenant_id = 'tenantid1234'
        self.keystone_id = 'keystone1234'
        self.name = 'name1234'

        secret_id = "idsecret1"
        datum_id = "iddatum1"
        kek_id = "idkek1"

        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"

        self.kek_tenant = models.KEKDatum()
        self.kek_tenant.id = kek_id
        self.kek_tenant.active = True
        self.kek_tenant.bind_completed = False
        self.kek_tenant.kek_label = "kek_label"
        self.kek_tenant.plugin_name = utils.generate_fullname_for(
            ctp.TestCryptoPlugin())

        self.datum = models.EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.kek_id = kek_id
        self.datum.kek_meta_tenant = self.kek_tenant
        self.datum.content_type = "text/plain"
        self.datum.cypher_text = "aaaa"  # base64 value.

        self.secret = create_secret(id_ref=secret_id,
                                    name=self.name,
                                    algorithm=self.secret_algorithm,
                                    bit_length=self.secret_bit_length,
                                    mode=self.secret_mode,
                                    encrypted_datum=self.datum)

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_id
        self.keystone_id = self.keystone_id
        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.secret_repo = mock.MagicMock()
        self.secret_repo.get.return_value = self.secret
        self.secret_repo.delete_entity_by_id.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.req = mock.MagicMock()
        self.req.accept = 'application/json'
        self.req.accept_encoding = 'gzip'
        self.resp = mock.MagicMock()

        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

        self.resource = res.SecretResource(self.crypto_mgr,
                                           self.tenant_repo,
                                           self.secret_repo,
                                           self.datum_repo,
                                           self.kek_repo)

    def test_should_get_secret_as_json(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertNotIn('content_encodings', resp_body)
        self.assertIn('content_types', resp_body)
        self.assertIn(self.datum.content_type,
                      resp_body['content_types'].itervalues())
        self.assertNotIn('mime_type', resp_body)

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

    def test_should_get_secret_meta_for_binary(self):
        self.req.accept = 'application/json'
        self.datum.content_type = "application/octet-stream"
        self.datum.cypher_text = 'aaaa'

        self.resource.on_get(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)

        self.assertEquals(self.resp.status, falcon.HTTP_200)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertIsNotNone(resp_body)
        self.assertIn('content_types', resp_body)
        self.assertIn(self.datum.content_type,
                      resp_body['content_types'].itervalues())

    def test_should_get_secret_as_binary(self):
        self.req.accept = 'application/octet-stream'
        # mock Content-Encoding header
        self.req.get_header.return_value = None
        self.datum.content_type = 'application/octet-stream'
        self.datum.cypher_text = 'aaaa'

        self.resource.on_get(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.assertEqual(self.resp.body, 'unencrypted_data')

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

        self.assertEqual(self.resp.status, falcon.HTTP_200)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)
        self.assertEqual(base64.b64encode('cypher_text'), datum.cypher_text)

        validate_datum(self, datum)

    def test_should_put_secret_as_binary(self):
        self._setup_for_puts()
        self.req.content_type = 'application/octet-stream'

        self.resource.on_put(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.assertEqual(self.resp.status, falcon.HTTP_200)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)

    def test_should_put_encoded_secret_as_binary(self):
        self._setup_for_puts()
        self.stream.read.return_value = base64.b64encode(self.payload)
        self.req.content_type = 'application/octet-stream'
        # mock Content-Encoding header
        self.req.get_header.return_value = 'base64'

        self.resource.on_put(self.req, self.resp, self.keystone_id,
                             self.secret.id)

        self.assertEqual(self.resp.status, falcon.HTTP_200)

    def test_should_fail_to_put_secret_with_unsupported_encoding(self):
        self._setup_for_puts()
        self.req.content_type = 'application/octet-stream'
        # mock Content-Encoding header
        self.req.get_header.return_value = 'bogusencoding'

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_put_secret_as_json(self):
        self._setup_for_puts()

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

    def test_should_fail_put_secret_no_payload(self):
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

    def test_should_fail_due_to_empty_payload(self):
        self._setup_for_puts()

        self.stream.read.return_value = ''

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_put(self.req, self.resp, self.keystone_id,
                                 self.secret.id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_due_to_plain_text_too_large(self):
        self._setup_for_puts()

        big_text = ''.join(['A' for x in xrange(
            2 * validators.DEFAULT_MAX_SECRET_BYTES)])
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
        self.payload = "plain_text"
        self.req.accept = "text/plain"
        self.req.content_type = "text/plain"
        # mock Content-Encoding header
        self.req.get_header.return_value = None

        self.secret.encrypted_data = []

        self.stream = mock.MagicMock()
        self.stream.read.return_value = self.payload
        self.req.stream = self.stream


class WhenCreatingOrdersUsingOrdersResource(unittest.TestCase):
    def setUp(self):
        self.secret_name = 'name'
        self.secret_payload_content_type = 'application/octet-stream'
        self.secret_algorithm = "aes"
        self.secret_bit_length = 128
        self.secret_mode = "cbc"

        self.tenant_internal_id = 'tenantid1234'
        self.tenant_keystone_id = 'keystoneid1234'

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_internal_id
        self.tenant.keystone_id = self.tenant_keystone_id

        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.order_repo = mock.MagicMock()
        self.order_repo.create_from.return_value = None

        self.queue_resource = mock.MagicMock()
        self.queue_resource.process_order.return_value = None

        self.stream = mock.MagicMock()

        order_req = {'secret': {'name': self.secret_name,
                                'payload_content_type':
                                self.secret_payload_content_type,
                                'algorithm': self.secret_algorithm,
                                'bit_length': self.secret_bit_length,
                                'mode': self.secret_mode}}
        self.json = json.dumps(order_req)
        self.stream.read.return_value = self.json

        self.req = mock.MagicMock()
        self.req.stream = self.stream

        self.resp = mock.MagicMock()
        self.resource = res.OrdersResource(self.tenant_repo, self.order_repo,
                                           self.queue_resource)

    def test_should_add_new_order(self):
        self.resource.on_post(self.req, self.resp, self.tenant_keystone_id)

        self.assertEquals(falcon.HTTP_202, self.resp.status)

        self.queue_resource.process_order \
            .assert_called_once_with(order_id=None,
                                     keystone_id=self.tenant_keystone_id)

        args, kwargs = self.order_repo.create_from.call_args
        order = args[0]
        self.assertIsInstance(order, models.Order)

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
        self.secret_algorithm = "algo"
        self.secret_bit_length = 512
        self.secret_mode = "cytype"
        self.params = {'offset': 2, 'limit': 2}

        self.num_orders = 10
        self.offset = 2
        self.limit = 2

        order_params = {'name': self.name,
                        'algorithm': self.secret_algorithm,
                        'bit_length': self.secret_bit_length,
                        'mode': self.secret_mode}

        self.orders = [create_order(id_ref='id' + str(id), **order_params) for
                       id in xrange(self.num_orders)]
        self.total = len(self.orders)
        self.order_repo = mock.MagicMock()
        self.order_repo.get_by_create_date.return_value = (self.orders,
                                                           self.offset,
                                                           self.limit,
                                                           self.total)
        self.tenant_repo = mock.MagicMock()

        self.queue_resource = mock.MagicMock()
        self.queue_resource.process_order.return_value = None

        self.req = mock.MagicMock()
        self.req.accept = 'application/json'
        self.req.get_param = mock.Mock()
        self.req.get_param.side_effect = [self.offset, self.limit]
        self.resp = mock.MagicMock()
        self.resource = res.OrdersResource(self.tenant_repo, self.order_repo,
                                           self.queue_resource)

    def test_should_get_list_orders(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.order_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
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

    def test_response_should_include_total(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)
        resp_body = jsonutils.loads(self.resp.body)
        self.assertIn('total', resp_body)
        self.assertEqual(resp_body['total'], self.total)

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

        self.order = create_order(id_ref="id1", name="name")

        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order
        self.order_repo.delete_entity_by_id.return_value = None

        self.req = mock.MagicMock()
        self.resp = mock.MagicMock()

        self.resource = res.OrderResource(self.order_repo)

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


class WhenAddingNavigationHrefs(unittest.TestCase):

    def setUp(self):
        self.resource_name = 'orders'
        self.keystone_id = '12345'
        self.num_elements = 100
        self.data = dict()

    def test_add_nav_hrefs_adds_next_only(self):
        offset = 0
        limit = 10

        data_with_hrefs = res.add_nav_hrefs(self.resource_name,
                                            self.keystone_id,
                                            offset, limit,
                                            self.num_elements,
                                            self.data)

        self.assertNotIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_both_next_and_previous(self):
        offset = 10
        limit = 10

        data_with_hrefs = res.add_nav_hrefs(self.resource_name,
                                            self.keystone_id,
                                            offset, limit,
                                            self.num_elements,
                                            self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_previous_only(self):
        offset = 90
        limit = 10

        data_with_hrefs = res.add_nav_hrefs(self.resource_name,
                                            self.keystone_id,
                                            offset, limit,
                                            self.num_elements,
                                            self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertNotIn('next', data_with_hrefs)


class WhenCreatingVerificationsUsingVerificationsResource(unittest.TestCase):
    def setUp(self):
        self.resource_type = 'image'
        self.resource_ref = 'http://www.images.com/v1/images/12345'
        self.resource_action = 'vm_attach'
        self.impersonation = True

        self.tenant_internal_id = 'tenantid1234'
        self.tenant_keystone_id = 'keystoneid1234'

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_internal_id
        self.tenant.keystone_id = self.tenant_keystone_id

        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.verification_repo = mock.MagicMock()
        self.verification_repo.create_from.return_value = None

        self.queue_resource = mock.MagicMock()
        self.queue_resource.process_verification.return_value = None

        self.stream = mock.MagicMock()

        self.verify_req = {'resource_type': self.resource_type,
                           'resource_ref': self.resource_ref,
                           'resource_action': self.resource_action,
                           'impersonation_allowed': self.impersonation}
        self.json = json.dumps(self.verify_req)
        self.stream.read.return_value = self.json

        self.req = mock.MagicMock()
        self.req.stream = self.stream

        self.resp = mock.MagicMock()
        self.resource = res.VerificationsResource(self.tenant_repo,
                                                  self.verification_repo,
                                                  self.queue_resource)

    def test_should_add_new_verification(self):
        self.resource.on_post(self.req, self.resp, self.tenant_keystone_id)

        self.assertEquals(falcon.HTTP_202, self.resp.status)

        self.queue_resource.process_verification \
            .assert_called_once_with(verification_id=None,
                                     keystone_id=self.tenant_keystone_id)

        args, kwargs = self.verification_repo.create_from.call_args
        verification = args[0]
        self.assertIsInstance(verification, models.Verification)

    def test_should_fail_add_new_verification_no_resource_ref(self):
        self.verify_req.pop('resource_ref')
        self.json = json.dumps(self.verify_req)
        self.stream.read.return_value = self.json

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp,
                                  self.tenant_keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_verification_unsupported_resource_type(self):
        self.verify_req['resource_type'] = 'not-a-valid-type'
        self.json = json.dumps(self.verify_req)
        self.stream.read.return_value = self.json

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp,
                                  self.tenant_keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)

    def test_should_fail_verification_bad_json(self):
        self.stream.read.return_value = ''

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_post(self.req, self.resp,
                                  self.tenant_keystone_id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_400, exception.status)


class WhenGettingOrDeletingVerificationUsingVerifyResource(unittest.TestCase):
    def setUp(self):
        self.tenant_keystone_id = 'keystoneid1234'
        self.requestor = 'requestor1234'

        self.verification = self._create_verification(id="id1")

        self.verify_repo = mock.MagicMock()
        self.verify_repo.get.return_value = self.verification
        self.verify_repo.delete_entity_by_id.return_value = None

        self.req = mock.MagicMock()
        self.resp = mock.MagicMock()

        self.resource = res.VerificationResource(self.verify_repo)

    def test_should_get_verification(self):
        self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                             self.verification.id)

        self.verify_repo.get \
            .assert_called_once_with(entity_id=self.verification.id,
                                     keystone_id=self.tenant_keystone_id,
                                     suppress_exception=True)

    def test_should_delete_verification(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_keystone_id,
                                self.verification.id)

        self.verify_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.verification.id,
                                     keystone_id=self.tenant_keystone_id)

    def test_should_throw_exception_for_get_when_verify_not_found(self):
        self.verify_repo.get.return_value = None

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_get(self.req, self.resp, self.tenant_keystone_id,
                                 self.verification.id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def test_should_throw_exception_for_delete_when_verify_not_found(self):
        self.verify_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")

        with self.assertRaises(falcon.HTTPError) as cm:
            self.resource.on_delete(self.req, self.resp,
                                    self.tenant_keystone_id,
                                    self.verification.id)
        exception = cm.exception
        self.assertEqual(falcon.HTTP_404, exception.status)

    def _create_verification(self, id="id",
                             resource_type='image',
                             resource_ref='http://www.images.com/images/123',
                             resource_action='vm_attach',
                             impersonation_allowed=True):
        """Generate a Verification entity instance."""
        verification = models.Verification()
        verification.id = id
        verification.resource_type = resource_type
        verification.resource_ref = resource_ref
        verification.resource_action = resource_action
        verification.impersonation_allowed = impersonation_allowed
        return verification


class WhenGettingVerificationsListUsingResource(unittest.TestCase):
    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.keystone_id = 'keystoneid1234'

        self.num_verifs = 10
        self.offset = 2
        self.limit = 2

        self.verifs = [create_verification(id_ref='id' + str(id_ref)) for
                       id_ref in xrange(self.num_verifs)]
        self.total = len(self.verifs)
        self.verif_repo = mock.MagicMock()
        self.verif_repo.get_by_create_date.return_value = (self.verifs,
                                                           self.offset,
                                                           self.limit,
                                                           self.total)
        self.tenant_repo = mock.MagicMock()

        self.queue_resource = mock.MagicMock()
        self.queue_resource.process_order.return_value = None

        self.req = mock.MagicMock()
        self.req.accept = 'application/json'
        self.req.get_param = mock.Mock()
        self.req.get_param.side_effect = [self.offset, self.limit, None, None,
                                          None, 0]
        self.resp = mock.MagicMock()
        self.resource = res.VerificationsResource(self.tenant_repo,
                                                  self.verif_repo,
                                                  self.queue_resource)

    def test_should_get_list_verifications(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.verif_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
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
                        (self.num_verifs + 2))

    def test_response_should_include_total(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)
        resp_body = jsonutils.loads(self.resp.body)
        self.assertIn('total', resp_body)
        self.assertEqual(resp_body['total'], self.total)

    def test_should_handle_no_orders(self):

        del self.verifs[:]

        self.resource.on_get(self.req, self.resp, self.keystone_id)

        self.verif_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=self.offset,
                                     limit_arg=self.limit,
                                     suppress_exception=True)

        resp_body = jsonutils.loads(self.resp.body)
        self.assertFalse('previous' in resp_body)
        self.assertFalse('next' in resp_body)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/v1/{0}/verifications' \
                   '?limit={1}&offset={2}'.format(keystone_id,
                                                  limit, offset)
        else:
            return '/v1/{0}/verifications'.format(self.keystone_id)
