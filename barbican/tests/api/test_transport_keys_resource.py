# Copyright (c) 2014 Red Hat, Inc.
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
This test module focuses on typical-flow business logic tests with the
transport key resource classes.
"""

import mock
import pecan
from six import moves
import webtest

from barbican.api import app
from barbican.api import controllers
from barbican.common import exception as excep
import barbican.context
from barbican.model import models
from barbican.tests import utils


def get_barbican_env(external_project_id):
    class NoopPolicyEnforcer(object):
        def enforce(self, *args, **kwargs):
            return

    kwargs = {'roles': None,
              'user': None,
              'project': external_project_id,
              'is_admin': True,
              'policy_enforcer': NoopPolicyEnforcer()}
    barbican_env = {'barbican.context':
                    barbican.context.RequestContext(**kwargs)}
    return barbican_env


SAMPLE_TRANSPORT_KEY = """
    -----BEGIN CERTIFICATE-----
    MIIDlDCCAnygAwIBAgIBGDANBgkqhkiG9w0BAQsFADBCMR8wHQYDVQQKDBZ0b21j
    YXQgMjggZG9tYWluIHRyeSAzMR8wHQYDVQQDDBZDQSBTaWduaW5nIENlcnRpZmlj
    YXRlMB4XDTE0MDMyNzA0MTU0OFoXDTE2MDMxNjA0MTU0OFowRTEfMB0GA1UECgwW
    dG9tY2F0IDI4IGRvbWFpbiB0cnkgMzEiMCAGA1UEAwwZRFJNIFRyYW5zcG9ydCBD
    ZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEjiTHn
    xWKKnzgBzR8kHo5YKXDbYi01ar0pAiJQ8Xx4MXj3Uf6ckfxvJ7Icb2PhigAgINLe
    td8butAXM0164kHeEMJWI2TG/+2f42Kla2KeU0bdgKbw1egyZreDvhGk/3P46LQt
    LtRBCb5eQWS2gTFocgA5phzRQnmSS4BRTh1MnGxaFLZsPOXqZKptAYaeXyLG63vL
    woBwFVGoodHrRrpYpCd+D6JABBdUEgSCaYG9JBDC5ElSjJnBlCNrUZ2kxokxbsQp
    UHm70LV9c+5n0o1VLJSqnUDuOkoovVWytlKbz0dw0KiTUDjkb4F4D6s+IePV1ufJ
    6cXvXCLLSQa42AcCAwEAAaOBkTCBjjAfBgNVHSMEGDAWgBSiQq7mBrAcTqqsPRvn
    l8pk4uZCWTBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9hbGVl
    LXdvcmtwYy5yZWRoYXQuY29tOjgyODAvY2Evb2NzcDAOBgNVHQ8BAf8EBAMCBPAw
    EwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBALmAtjactFHA
    d4nBFpwpwh3tGhkfwoSCuKThX54UXsJawQrx5gaxP0JE7YVLDRe4jn+RHjkXxdxX
    Xt4IugdTsPNq0nvWVAzwZwoGlJZjqghHpD3AB4E5DEoOnVnmJRLFLF0Xg/R5Sw3F
    j9wdVE/hGShrF+fOqNZhTG2Mf4f9TUR1Y8PtoBmtkwnFUoeiaI+Nq6Dd1Qw8ysar
    i/sOzOOjou4vcbYnrKnn2hlSgF6toza0BCGVA8fMyGBh16JtTR1REL7Bf0m3ZQDy
    4hjmPjvUTN3YO2RlLVZXArhhmqcQzCl94P37pAEN/JhAIYvQ2PPM/ofK9XHc9u9j
    rQJGkMpu7ck=
    -----END CERTIFICATE-----"""


def create_transport_key(id_ref="id",
                         plugin_name="default_plugin",
                         transport_key=None):
    """Generate a transport cert entity instance."""
    tkey = models.TransportKey(plugin_name, transport_key)
    tkey.id = id_ref
    return tkey


class FunctionalTest(utils.BaseTestCase):

    def setUp(self):
        super(FunctionalTest, self).setUp()
        root = self.root
        config = {'app': {'root': root}}
        pecan.set_config(config, overwrite=True)
        self.app = webtest.TestApp(pecan.make_app(root))

    def tearDown(self):
        super(FunctionalTest, self).tearDown()
        pecan.set_config({}, overwrite=True)

    @property
    def root(self):
        return controllers.versions.VersionController()


class WhenGettingTransKeysListUsingTransportKeysResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingTransKeysListUsingTransportKeysResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            transport_keys = controllers.transportkeys.TransportKeysController(
                self.repo)

        return RootController()

    def _init(self):
        self.plugin_name = "default_plugin"
        self.external_project_id = 'keystoneid1234'
        self.params = {'offset': 2, 'limit': 2}

        self.transport_key = SAMPLE_TRANSPORT_KEY
        self.num_keys = 10
        self.offset = 2
        self.limit = 2

        tk_params = {'plugin_name': self.plugin_name,
                     'transport_key': self.transport_key}

        self.tkeys = [create_transport_key(
            id_ref='id' + str(tkid), **tk_params)
            for tkid in moves.range(self.num_keys)]
        self.total = len(self.tkeys)
        self.repo = mock.MagicMock()
        self.repo.get_by_create_date.return_value = (self.tkeys,
                                                     self.offset,
                                                     self.limit,
                                                     self.total)
        self.params = {
            'offset': self.offset,
            'limit': self.limit
        }

    def test_should_get_list_transport_keys(self):
        resp = self.app.get('/transport_keys/',
                            self.params)

        self.repo.get_by_create_date.assert_called_once_with(
            plugin_name=None,
            offset_arg=u'{0}'.format(self.offset),
            limit_arg=u'{0}'.format(self.limit),
            suppress_exception=True
        )

        self.assertIn('previous', resp.namespace)
        self.assertIn('next', resp.namespace)

        url_nav_next = self._create_url(self.external_project_id,
                                        self.offset + self.limit, self.limit)
        self.assertEqual(1, resp.body.count(url_nav_next))

        url_nav_prev = self._create_url(self.external_project_id,
                                        0, self.limit)
        self.assertEqual(1, resp.body.count(url_nav_prev))

        url_hrefs = self._create_url(self.external_project_id)
        self.assertEqual((self.num_keys + 2), resp.body.count(url_hrefs))

    def test_response_should_include_total(self):
        resp = self.app.get('/transport_keys/',
                            self.params)
        self.assertIn('total', resp.namespace)
        self.assertEqual(self.total, resp.namespace['total'])

    def test_should_handle_no_transport_keys(self):

        del self.tkeys[:]

        resp = self.app.get('/transport_keys/',
                            self.params)

        self.repo.get_by_create_date.assert_called_once_with(
            plugin_name=None,
            offset_arg=u'{0}'.format(self.offset),
            limit_arg=u'{0}'.format(self.limit),
            suppress_exception=True
        )

        self.assertNotIn('previous', resp.namespace)
        self.assertNotIn('next', resp.namespace)

    def _create_url(self, external_project_id, offset_arg=None,
                    limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/transport_keys?limit={0}&offset={1}'.format(
                limit, offset)
        else:
            return '/transport_keys'


class WhenCreatingTransKeysListUsingTransportKeysResource(FunctionalTest):
    def setUp(self):
        super(
            WhenCreatingTransKeysListUsingTransportKeysResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            transport_keys = controllers.transportkeys.TransportKeysController(
                self.repo)

        return RootController()

    def _init(self):
        self.plugin_name = "default_plugin"
        self.external_project_id = 'keystoneid1234'

        self.repo = mock.MagicMock()
        self.transport_key_req = {
            'plugin_name': self.plugin_name,
            'transport_key': SAMPLE_TRANSPORT_KEY
        }

    def test_should_add_new_transport_key(self):
        resp = self.app.post_json(
            '/transport_keys/',
            self.transport_key_req
        )
        self.assertEqual(201, resp.status_int)

        args, kwargs = self.repo.create_from.call_args
        order = args[0]
        self.assertIsInstance(order, models.TransportKey)

    def test_should_raise_add_new_transport_key_no_secret(self):
        resp = self.app.post_json(
            '/transport_keys/',
            {},
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_should_raise_add_new_transport_key_bad_json(self):
        resp = self.app.post(
            '/transport_keys/',
            '',
            expect_errors=True,
            content_type='application/json'
        )
        self.assertEqual(400, resp.status_int)

    def test_should_raise_add_new_transport_key_no_content_type_header(self):
        resp = self.app.post(
            '/transport_keys/',
            self.transport_key_req,
            expect_errors=True,
        )
        self.assertEqual(415, resp.status_int)


class WhenGettingOrDeletingTransKeyUsingTransportKeyResource(FunctionalTest):

    def setUp(self):
        super(
            WhenGettingOrDeletingTransKeyUsingTransportKeyResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            transport_keys = controllers.transportkeys.TransportKeysController(
                self.repo)

        return RootController()

    def _init(self):
        self.external_project_id = 'keystoneid1234'
        self.transport_key = SAMPLE_TRANSPORT_KEY
        self.tkey_id = "id1"

        self.tkey = create_transport_key(
            id_ref=self.tkey_id,
            plugin_name="default_plugin",
            transport_key=self.transport_key)

        self.repo = mock.MagicMock()
        self.repo.get.return_value = self.tkey

    def test_should_get_transport_key(self):
        self.app.get('/transport_keys/{0}/'.format(self.tkey.id))

        self.repo.get.assert_called_once_with(entity_id=self.tkey.id)

    def test_should_throw_exception_for_get_when_trans_key_not_found(self):
        self.repo.get.return_value = None
        resp = self.app.get(
            '/transport_keys/{0}/'.format(self.tkey.id),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)

    def test_should_delete_transport_key(self):
        self.app.delete('/transport_keys/{0}/'.format(self.tkey.id))
        self.repo.delete_entity_by_id.assert_called_once_with(
            entity_id=self.tkey.id,
            external_project_id=self.external_project_id)

    def test_should_throw_exception_for_delete_when_trans_key_not_found(self):
        self.repo.delete_entity_by_id.side_effect = excep.NotFound(
            "Test not found exception")
        resp = self.app.delete(
            '/transport_keys/{0}/'.format(self.tkey.id),
            expect_errors=True
        )
        self.assertEqual(404, resp.status_int)
