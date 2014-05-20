# Copyright (c) 2013-2014 Rackspace, Inc.
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
import urllib

import mock
import testtools
import pecan
from webtest import TestApp

from barbican.api import strip_whitespace
from barbican.api import app
from barbican.api import controllers
from barbican.common import exception as excep
from barbican.common import utils
from barbican.common import validators
from barbican.crypto import extension_manager as em
from barbican.model import models
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
    secret.id = id_ref
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


def create_container(id_ref):
    """Generate a Container entity instance."""
    container = models.Container()
    container.id = id_ref
    container.name = 'test name'
    container.type = 'rsa'
    container_secret = models.ContainerSecret()
    container_secret.container_id = id
    container_secret.secret_id = '123'
    container.container_secrets.append(container_secret)
    return container


class FunctionalTest(testtools.TestCase):

    def setUp(self):
        super(FunctionalTest, self).setUp()
        root = self.root
        config = {'app': {'root': root}}
        pecan.set_config(config, overwrite=True)
        self.app = TestApp(pecan.make_app(root))

    def tearDown(self):
        super(FunctionalTest, self).tearDown()
        pecan.set_config({}, overwrite=True)

    @property
    def root(self):
        return controllers.versions.VersionController()


class WhenTestingVersionResource(FunctionalTest):

    def test_should_return_200_on_get(self):
        resp = self.app.get('/')
        self.assertEqual(200, resp.status_int)

    def test_should_return_version_json(self):
        resp = self.app.get('/')

        self.assertTrue('v1' in resp.json)
        self.assertEqual('current', resp.json['v1'])


class BaseSecretsResource(FunctionalTest):
    """Base test class for the Secrets resource."""

    def setUp(self):
        super(BaseSecretsResource, self).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController(
                self.crypto_mgr, self.tenant_repo, self.secret_repo,
                self.tenant_secret_repo, self.datum_repo, self.kek_repo
            )

        return RootController()

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

        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

    def _test_should_add_new_secret_with_expiration(self):
        expiration = '2114-02-28 12:14:44.180394-05:00'
        self.secret_req.update({'expiration': expiration})

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )

        self.assertEqual(resp.status_int, 201)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        expected = expiration[:-6].replace('12', '17', 1)
        self.assertEqual(expected, str(secret.expiration))

    def _test_should_add_new_secret_one_step(self, check_tenant_id=True):
        """Test the one-step secret creation.

        :param check_tenant_id: True if the retrieved Tenant id needs to be
        verified, False to skip this check (necessary for new-Tenant flows).
        """
        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)

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
        self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            {'name': self.name}
        )

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
        self.app.post_json('/%s/secrets/' % self.keystone_id, self.secret_req)

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

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 413)

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

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        assert resp.status_int == 400


class WhenCreatingPlainTextSecretsUsingSecretsResource(BaseSecretsResource):

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

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_create_secret_content_type_text_plain(self):
        # payload_content_type has trailing space
        self.secret_req = {'name': self.name,
                           'payload_content_type': 'text/plain ',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': self.payload}

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)

        self.secret_req = {'name': self.name,
                           'payload_content_type': '  text/plain',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': self.payload}

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)

    def test_create_secret_content_type_text_plain_space_charset_utf8(self):
        # payload_content_type has trailing space
        self.secret_req = {'name': self.name,
                           'payload_content_type':
                           'text/plain; charset=utf-8 ',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': self.payload}

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)

        self.secret_req = {'name': self.name,
                           'payload_content_type':
                           '  text/plain; charset=utf-8',
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'mode': self.secret_mode,
                           'payload': self.payload}

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)

    def test_create_secret_with_only_content_type(self):
        # No payload just content_type
        self.secret_req = {'payload_content_type':
                           'text/plain'}
        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

        self.secret_req = {'payload_content_type':
                           'text/plain',
                           'payload': 'somejunk'}
        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req
        )
        self.assertEqual(resp.status_int, 201)


class WhenCreatingBinarySecretsUsingSecretsResource(BaseSecretsResource):

    @property
    def root(self):
        self._init(payload="...lOtfqHaUUpe6NqLABgquYQ==",
                   payload_content_type='application/octet-stream',
                   payload_content_encoding='base64')
        return super(WhenCreatingBinarySecretsUsingSecretsResource, self).root

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
        self.secret_req = {
            'name': self.name,
            'algorithm': self.secret_algorithm,
            'bit_length': self.secret_bit_length,
            'mode': self.secret_mode,
            'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
            'payload_content_type': 'application/octet-stream'
        }
        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_create_secret_fails_with_binary_payload_bad_encoding(self):
        self.secret_req = {
            'name': self.name,
            'algorithm': self.secret_algorithm,
            'bit_length': self.secret_bit_length,
            'mode': self.secret_mode,
            'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'bogus64'
        }

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_create_secret_fails_with_binary_payload_no_content_type(self):
        self.secret_req = {
            'name': self.name,
            'algorithm': self.secret_algorithm,
            'bit_length': self.secret_bit_length,
            'mode': self.secret_mode,
            'payload': 'lOtfqHaUUpe6NqLABgquYQ==',
            'payload_content_encoding': 'base64'
        }

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_create_secret_fails_with_bad_payload(self):
        self.secret_req = {
            'name': self.name,
            'algorithm': self.secret_algorithm,
            'bit_length': self.secret_bit_length,
            'mode': self.secret_mode,
            'payload': 'AAAAAAAAA',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64'
        }

        resp = self.app.post_json(
            '/%s/secrets/' % self.keystone_id,
            self.secret_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)


class WhenGettingSecretsListUsingSecretsResource(FunctionalTest):

    def setUp(self):
        super(WhenGettingSecretsListUsingSecretsResource, self).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController(
                self.crypto_mgr, self.tenant_repo, self.secret_repo,
                self.tenant_secret_repo, self.datum_repo, self.kek_repo
            )

        return RootController()

    def _init(self):
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

        self.params = {'offset': self.offset,
                       'limit': self.limit,
                       'name': None,
                       'alg': None,
                       'bits': 0,
                       'mode': None}

    def test_should_list_secrets_by_name(self):
        # Quote the name parameter to simulate how it would be
        # received in practice via a REST-ful GET query.
        self.params['name'] = urllib.quote_plus(self.name)

        resp = self.app.get(
            '/%s/secrets/' % self.keystone_id,
            dict((k, v) for k, v in self.params.items() if v is not None)
        )
        # Verify that the name is unquoted correctly in the
        # secrets.on_get function prior to searching the repo.
        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True,
                                     name=self.name,
                                     alg=None, mode=None,
                                     bits=0)

        self.assertIn('secrets', resp.namespace)
        secrets = resp.namespace['secrets']
        # The result should be the unquoted name
        self.assertEqual(secrets[0]['name'], self.name)

    def test_should_get_list_secrets(self):
        resp = self.app.get(
            '/%s/secrets/' % self.keystone_id,
            dict((k, v) for k, v in self.params.items() if v is not None)
        )

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True,
                                     name='', alg=None, mode=None,
                                     bits=0)

        self.assertTrue('previous' in resp.namespace)
        self.assertTrue('next' in resp.namespace)

        url_nav_next = self._create_url(self.keystone_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.keystone_id,
                                        0, self.limit)
        self.assertTrue(resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.keystone_id)
        self.assertTrue(resp.body.count(url_hrefs) ==
                        (self.num_secrets + 2))

    def test_response_should_include_total(self):
        resp = self.app.get(
            '/%s/secrets/' % self.keystone_id,
            dict((k, v) for k, v in self.params.items() if v is not None)
        )

        self.assertIn('total', resp.namespace)
        self.assertEqual(resp.namespace['total'], self.total)

    def test_should_handle_no_secrets(self):

        del self.secrets[:]

        resp = self.app.get(
            '/%s/secrets/' % self.keystone_id,
            dict((k, v) for k, v in self.params.items() if v is not None)
        )

        self.secret_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True,
                                     name='', alg=None, mode=None,
                                     bits=0)

        self.assertFalse('previous' in resp.namespace)
        self.assertFalse('next' in resp.namespace)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/{0}/secrets?limit={1}&offset={2}'.format(keystone_id,
                                                              limit,
                                                              offset)
        else:
            return '/{0}/secrets'.format(keystone_id)


class WhenGettingPuttingOrDeletingSecretUsingSecretResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingPuttingOrDeletingSecretUsingSecretResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController(
                self.crypto_mgr, self.tenant_repo, self.secret_repo,
                self.tenant_secret_repo, self.datum_repo, self.kek_repo
            )

        return RootController()

    def _init(self):
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

        self.tenant_secret_repo = mock.MagicMock()

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

    def test_should_get_secret_as_json(self):
        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'}
        )
        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)
        self.assertEquals(resp.status_int, 200)

        self.assertNotIn('content_encodings', resp.namespace)
        self.assertIn('content_types', resp.namespace)
        self.assertIn(self.datum.content_type,
                      resp.namespace['content_types'].itervalues())
        self.assertNotIn('mime_type', resp.namespace)

    def test_should_get_secret_as_plain(self):
        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'text/plain'}
        )

        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)
        self.assertEquals(resp.status_int, 200)

        self.assertIsNotNone(resp.body)

    def test_should_get_secret_meta_for_binary(self):
        self.datum.content_type = "application/octet-stream"
        self.datum.cypher_text = 'aaaa'

        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'}
        )

        self.secret_repo \
            .get.assert_called_once_with(entity_id=self.secret.id,
                                         keystone_id=self.keystone_id,
                                         suppress_exception=True)

        self.assertEqual(resp.status_int, 200)

        self.assertIsNotNone(resp.namespace)
        self.assertIn('content_types', resp.namespace)
        self.assertIn(self.datum.content_type,
                      resp.namespace['content_types'].itervalues())

    def test_should_get_secret_as_binary(self):
        self.datum.content_type = "application/octet-stream"
        self.datum.cypher_text = 'aaaa'

        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={
                'Accept': 'application/octet-stream',
                'Accept-Encoding': 'gzip'
            }
        )

        self.assertEqual(resp.body, 'unencrypted_data')

    def test_should_throw_exception_for_get_when_secret_not_found(self):
        self.secret_repo.get.return_value = None

        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)

    def test_should_throw_exception_for_get_when_accept_not_supported(self):
        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'bogusaccept', 'Accept-Encoding': 'gzip'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 406)

    def test_should_throw_exception_for_get_when_datum_not_available(self):
        self.secret.encrypted_data = []

        resp = self.app.get(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            headers={'Accept': 'text/plain'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)

    def test_should_put_secret_as_plain(self):
        self.secret.encrypted_data = []

        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
        )

        self.assertEqual(resp.status_int, 200)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)
        self.assertEqual(base64.b64encode('cypher_text'), datum.cypher_text)

        validate_datum(self, datum)

    def test_should_put_secret_as_binary(self):
        self.secret.encrypted_data = []

        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/octet-stream'
            },
        )

        self.assertEqual(resp.status_int, 200)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)

    def test_should_put_encoded_secret_as_binary(self):
        self.secret.encrypted_data = []
        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            base64.b64encode('plain text'),
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/octet-stream',
                'Content-Encoding': 'base64'
            },
        )

        self.assertEqual(resp.status_int, 200)

    def test_should_fail_to_put_secret_with_unsupported_encoding(self):
        self.secret.encrypted_data = []
        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/octet-stream',
                'Content-Encoding': 'bogusencoding'
            },
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 400)

    def test_should_fail_put_secret_as_json(self):
        self.secret.encrypted_data = []
        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/json'
            },
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 415)

    def test_should_fail_put_secret_not_found(self):
        # Force error, due to secret not found.
        self.secret_repo.get.return_value = None

        self.secret.encrypted_data = []
        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 404)

    def test_should_fail_put_secret_no_payload(self):
        self.secret.encrypted_data = []
        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            # response.body = None
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(resp.status_int, 400)

    def test_should_fail_put_secret_with_existing_datum(self):
        # Force error due to secret already having data
        self.secret.encrypted_data = [self.datum]

        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            'plain text',
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 409)

    def test_should_fail_due_to_empty_payload(self):
        self.secret.encrypted_data = []

        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            '',
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_should_fail_due_to_plain_text_too_large(self):
        big_text = ''.join(['A' for x in xrange(
            2 * validators.DEFAULT_MAX_SECRET_BYTES)])

        self.secret.encrypted_data = []

        resp = self.app.put(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            big_text,
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 413)

    def test_should_delete_secret(self):
        self.app.delete(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id)
        )
        self.secret_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.secret.id,
                                     keystone_id=self.keystone_id)

    def test_should_throw_exception_for_delete_when_secret_not_found(self):
        self.secret_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")

        resp = self.app.delete(
            '/%s/secrets/%s/' % (self.keystone_id, self.secret.id),
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)


class WhenCreatingOrdersUsingOrdersResource(FunctionalTest):
    def setUp(self):
        super(
            WhenCreatingOrdersUsingOrdersResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            orders = controllers.orders.OrdersController(self.tenant_repo,
                                                         self.order_repo,
                                                         self.queue_resource)

        return RootController()

    def _init(self):
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

        self.order_req = {
            'secret': {
                'name': self.secret_name,
                'payload_content_type':
                self.secret_payload_content_type,
                'algorithm': self.secret_algorithm,
                'bit_length': self.secret_bit_length,
                'mode': self.secret_mode
            }
        }

    def test_should_add_new_order(self):
        resp = self.app.post_json(
            '/%s/orders/' % self.tenant_keystone_id,
            self.order_req
        )
        self.assertEqual(resp.status_int, 202)

        self.queue_resource.process_order \
            .assert_called_once_with(order_id=None,
                                     keystone_id=self.tenant_keystone_id)

        args, kwargs = self.order_repo.create_from.call_args
        order = args[0]
        self.assertIsInstance(order, models.Order)

    def test_should_fail_add_new_order_no_secret(self):
        resp = self.app.post_json(
            '/%s/orders/' % self.tenant_keystone_id,
            {},
            expect_errors=True
        )
        self.assertEquals(resp.status_int, 400)

    def test_should_fail_add_new_order_bad_json(self):
        resp = self.app.post(
            '/%s/orders/' % self.tenant_keystone_id,
            '',
            expect_errors=True
        )
        self.assertEquals(resp.status_int, 400)


class WhenGettingOrdersListUsingOrdersResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingOrdersListUsingOrdersResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            orders = controllers.orders.OrdersController(self.tenant_repo,
                                                         self.order_repo,
                                                         self.queue_resource)

        return RootController()

    def _init(self):
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

        self.params = {
            'offset': self.offset,
            'limit': self.limit
        }

    def test_should_get_list_orders(self):
        resp = self.app.get('/%s/orders/' % self.keystone_id, self.params)

        self.order_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True)

        self.assertTrue('previous' in resp.namespace)
        self.assertTrue('next' in resp.namespace)

        url_nav_next = self._create_url(self.keystone_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.keystone_id,
                                        0, self.limit)
        self.assertTrue(resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.keystone_id)
        self.assertTrue(resp.body.count(url_hrefs) ==
                        (self.num_orders + 2))

    def test_response_should_include_total(self):
        resp = self.app.get('/%s/orders/' % self.keystone_id, self.params)
        self.assertIn('total', resp.namespace)
        self.assertEqual(resp.namespace['total'], self.total)

    def test_should_handle_no_orders(self):

        del self.orders[:]

        resp = self.app.get('/%s/orders/' % self.keystone_id, self.params)

        self.order_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True)

        self.assertFalse('previous' in resp.namespace)
        self.assertFalse('next' in resp.namespace)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/{0}/orders?limit={1}&offset={2}'.format(keystone_id,
                                                             limit,
                                                             offset)
        else:
            return '/{0}/orders'.format(self.keystone_id)


class WhenGettingOrDeletingOrderUsingOrderResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingOrDeletingOrderUsingOrderResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            orders = controllers.orders.OrdersController(self.tenant_repo,
                                                         self.order_repo,
                                                         self.queue_resource)

        return RootController()

    def _init(self):
        self.tenant_keystone_id = 'keystoneid1234'
        self.requestor = 'requestor1234'

        self.order = create_order(id_ref="id1", name="name")

        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order
        self.order_repo.delete_entity_by_id.return_value = None

        self.tenant_repo = mock.MagicMock()
        self.queue_resource = mock.MagicMock()

    def test_should_get_order(self):
        self.app.get('/%s/orders/%s/' % (self.tenant_keystone_id,
                                         self.order.id))

        self.order_repo.get \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.tenant_keystone_id,
                                     suppress_exception=True)

    def test_should_delete_order(self):
        self.app.delete('/%s/orders/%s/' % (self.tenant_keystone_id,
                                            self.order.id))
        self.order_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.tenant_keystone_id)

    def test_should_throw_exception_for_get_when_order_not_found(self):
        self.order_repo.get.return_value = None
        resp = self.app.get(
            '/%s/orders/%s/' % (self.tenant_keystone_id, self.order.id),
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)

    def test_should_throw_exception_for_delete_when_order_not_found(self):
        self.order_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")
        resp = self.app.delete(
            '/%s/orders/%s/' % (self.tenant_keystone_id, self.order.id),
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)


class WhenAddingNavigationHrefs(testtools.TestCase):

    def setUp(self):
        super(WhenAddingNavigationHrefs, self).setUp()

        self.resource_name = 'orders'
        self.keystone_id = '12345'
        self.num_elements = 100
        self.data = dict()

    def test_add_nav_hrefs_adds_next_only(self):
        offset = 0
        limit = 10

        data_with_hrefs = controllers.hrefs.add_nav_hrefs(self.resource_name,
                                                          self.keystone_id,
                                                          offset, limit,
                                                          self.num_elements,
                                                          self.data)

        self.assertNotIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_both_next_and_previous(self):
        offset = 10
        limit = 10

        data_with_hrefs = controllers.hrefs.add_nav_hrefs(self.resource_name,
                                                          self.keystone_id,
                                                          offset, limit,
                                                          self.num_elements,
                                                          self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_previous_only(self):
        offset = 90
        limit = 10

        data_with_hrefs = controllers.hrefs.add_nav_hrefs(self.resource_name,
                                                          self.keystone_id,
                                                          offset, limit,
                                                          self.num_elements,
                                                          self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertNotIn('next', data_with_hrefs)


class TestingJsonSanitization(testtools.TestCase):

    def test_json_sanitization_without_array(self):
        json_without_array = {"name": "name", "algorithm": "AES",
                              "payload_content_type": "  text/plain   ",
                              "mode": "CBC", "bit_length": 256,
                              "payload": "not-encrypted"}

        self.assertTrue(json_without_array['payload_content_type']
                        .startswith(' '), "whitespace should be there")
        self.assertTrue(json_without_array['payload_content_type']
                        .endswith(' '), "whitespace should be there")
        strip_whitespace(json_without_array)
        self.assertFalse(json_without_array['payload_content_type']
                         .startswith(' '), "whitespace should be gone")
        self.assertFalse(json_without_array['payload_content_type']
                         .endswith(' '), "whitespace should be gone")

    def test_json_sanitization_with_array(self):
        json_with_array = {"name": "name", "algorithm": "AES",
                           "payload_content_type": "text/plain",
                           "mode": "CBC", "bit_length": 256,
                           "payload": "not-encrypted",
                           "an-array":
                           [{"name": " item 1"},
                            {"name": "item2 "}]}

        self.assertTrue(json_with_array['an-array'][0]['name']
                        .startswith(' '), "whitespace should be there")
        self.assertTrue(json_with_array['an-array'][1]['name']
                        .endswith(' '), "whitespace should be there")
        strip_whitespace(json_with_array)
        self.assertFalse(json_with_array['an-array'][0]['name']
                         .startswith(' '), "whitespace should be gone")
        self.assertFalse(json_with_array['an-array'][1]['name']
                         .endswith(' '), "whitespace should be gone")


class WhenCreatingContainersUsingContainersResource(FunctionalTest):
    def setUp(self):
        super(
            WhenCreatingContainersUsingContainersResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController(
                self.tenant_repo, self.container_repo, self.secret_repo
            )

        return RootController()

    def _init(self):
        self.name = 'test container name'
        self.type = 'generic'
        self.secret_refs = [
            {
                'name': 'test secret 1',
                'secret_ref': '123'
            },
            {
                'name': 'test secret 2',
                'secret_ref': '123'
            },
            {
                'name': 'test secret 3',
                'secret_ref': '123'
            }
        ]

        self.tenant_internal_id = 'tenantid1234'
        self.tenant_keystone_id = 'keystoneid1234'

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_internal_id
        self.tenant.keystone_id = self.tenant_keystone_id

        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.container_repo = mock.MagicMock()
        self.container_repo.create_from.return_value = None

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

    def test_should_add_new_container(self):
        resp = self.app.post_json(
            '/%s/containers/' % self.tenant_keystone_id,
            self.container_req
        )
        self.assertEqual(resp.status_int, 202)

        args, kwargs = self.container_repo.create_from.call_args
        container = args[0]
        self.assertIsInstance(container, models.Container)

    def test_should_fail_container_bad_json(self):
        resp = self.app.post(
            '/%s/containers/' % self.tenant_keystone_id,
            '',
            expect_errors=True
        )
        self.assertEquals(resp.status_int, 400)

    def test_should_throw_exception_when_secret_ref_doesnt_exist(self):
        self.secret_repo.get.return_value = None
        resp = self.app.post_json(
            '/%s/containers/' % self.tenant_keystone_id,
            self.container_req,
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 404)


class WhenGettingOrDeletingContainerUsingContainerResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingOrDeletingContainerUsingContainerResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController(
                self.tenant_repo, self.container_repo, self.secret_repo
            )

        return RootController()

    def _init(self):
        self.tenant_keystone_id = 'keystoneid1234'
        self.tenant_internal_id = 'tenantid1234'

        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_internal_id
        self.tenant.keystone_id = self.tenant_keystone_id

        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.container = create_container(id_ref='id1')

        self.container_repo = mock.MagicMock()
        self.container_repo.get.return_value = self.container
        self.container_repo.delete_entity_by_id.return_value = None

        self.secret_repo = mock.MagicMock()

    def test_should_get_container(self):
        self.app.get('/%s/containers/%s/' % (
            self.tenant_keystone_id, self.container.id
        ))

        self.container_repo.get \
            .assert_called_once_with(entity_id=self.container.id,
                                     keystone_id=self.tenant_keystone_id,
                                     suppress_exception=True)

    def test_should_delete_container(self):
        self.app.delete('/%s/containers/%s/' % (
            self.tenant_keystone_id, self.container.id
        ))

        self.container_repo.delete_entity_by_id \
            .assert_called_once_with(entity_id=self.container.id,
                                     keystone_id=self.tenant_keystone_id)

    def test_should_throw_exception_for_get_when_container_not_found(self):
        self.container_repo.get.return_value = None
        resp = self.app.get('/%s/containers/%s/' % (
            self.tenant_keystone_id, self.container.id
        ), expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_should_throw_exception_for_delete_when_container_not_found(self):
        self.container_repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")

        resp = self.app.delete('/%s/containers/%s/' % (
            self.tenant_keystone_id, self.container.id
        ), expect_errors=True)
        self.assertEqual(resp.status_int, 404)


class WhenGettingContainersListUsingResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingContainersListUsingResource, self
        ).setUp()
        self.app = TestApp(app.PecanAPI(self.root))

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController(
                self.tenant_repo, self.container_repo, self.secret_repo
            )

        return RootController()

    def _init(self):
        self.tenant_id = 'tenant1234'
        self.keystone_id = 'keystoneid1234'

        self.num_containers = 10
        self.offset = 2
        self.limit = 2

        self.containers = [create_container(id_ref='id' + str(id_ref)) for
                           id_ref in xrange(self.num_containers)]
        self.total = len(self.containers)
        self.container_repo = mock.MagicMock()
        self.container_repo.get_by_create_date.return_value = (self.containers,
                                                               self.offset,
                                                               self.limit,
                                                               self.total)
        self.tenant_repo = mock.MagicMock()
        self.secret_repo = mock.MagicMock()

        self.params = {
            'offset': self.offset,
            'limit': self.limit,
        }

    def test_should_get_list_containers(self):
        resp = self.app.get(
            '/%s/containers/' % self.keystone_id,
            self.params
        )

        self.container_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True)

        self.assertTrue('previous' in resp.namespace)
        self.assertTrue('next' in resp.namespace)

        url_nav_next = self._create_url(self.keystone_id,
                                        self.offset + self.limit, self.limit)
        self.assertTrue(resp.body.count(url_nav_next) == 1)

        url_nav_prev = self._create_url(self.keystone_id,
                                        0, self.limit)
        self.assertTrue(resp.body.count(url_nav_prev) == 1)

        url_hrefs = self._create_url(self.keystone_id)
        self.assertTrue(resp.body.count(url_hrefs) ==
                        (self.num_containers + 2))

    def test_response_should_include_total(self):
        resp = self.app.get(
            '/%s/containers/' % self.keystone_id,
            self.params
        )
        self.assertIn('total', resp.namespace)
        self.assertEqual(resp.namespace['total'], self.total)

    def test_should_handle_no_containers(self):

        del self.containers[:]

        resp = self.app.get(
            '/%s/containers/' % self.keystone_id,
            self.params
        )

        self.container_repo.get_by_create_date \
            .assert_called_once_with(self.keystone_id,
                                     offset_arg=u'{0}'.format(self.offset),
                                     limit_arg=u'{0}'.format(self.limit),
                                     suppress_exception=True)

        self.assertFalse('previous' in resp.namespace)
        self.assertFalse('next' in resp.namespace)

    def _create_url(self, keystone_id, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/{0}/containers' \
                   '?limit={1}&offset={2}'.format(keystone_id,
                                                  limit, offset)
        else:
            return '/{0}/containers'.format(self.keystone_id)
