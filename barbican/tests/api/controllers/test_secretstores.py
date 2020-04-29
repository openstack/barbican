# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from unittest import mock

from oslo_utils import uuidutils

from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin.interface import secret_store
from barbican.tests import utils


class SecretStoresMixin(utils.MultipleBackendsTestCase):

    def _create_project(self):
        session = repos.get_project_repository().get_session()

        project = models.Project()
        project.external_id = ("keystone_project_id" +
                               uuidutils.generate_uuid(dashed=False))
        project.save(session=session)
        return project

    def _create_project_store(self, project_id, secret_store_id):
        proj_store_repo = repos.get_project_secret_store_repository()
        session = proj_store_repo.get_session()

        proj_model = models.ProjectSecretStore(project_id, secret_store_id)

        proj_s_store = proj_store_repo.create_from(proj_model, session)
        proj_s_store.save(session=session)
        return proj_s_store

    def _init_multiple_backends(self, enabled=True, global_default_index=0):

        store_plugin_names = ['store_crypto', 'kmip_plugin', 'store_crypto']
        crypto_plugin_names = ['p11_crypto', '', 'simple_crypto']

        self.init_via_conf_file(store_plugin_names,
                                crypto_plugin_names, enabled=enabled,
                                global_default_index=global_default_index)

        with mock.patch('barbican.plugin.crypto.p11_crypto.P11CryptoPlugin.'
                        '_create_pkcs11'), \
                mock.patch('kmip.pie.client.ProxyKmipClient'):

            secret_store.SecretStorePluginManager()


class WhenTestingSecretStores(utils.BarbicanAPIBaseTestCase,
                              SecretStoresMixin):

    def setUp(self):
        super(WhenTestingSecretStores, self).setUp()
        self.secret_store_repo = repos.get_secret_stores_repository()

    def test_should_get_all_secret_stores(self):

        g_index = 2  # global default index in plugins list
        self._init_multiple_backends(global_default_index=g_index)

        resp = self.app.get('/secret-stores', expect_errors=False)
        self.assertEqual(200, resp.status_int)
        secret_stores_data = resp.json.get('secret_stores')

        self.assertEqual(3, len(secret_stores_data))

        for i, secret_data in enumerate(secret_stores_data):
            self.assertEqual(i == g_index, secret_data['global_default'])
            self.assertIsNotNone(secret_data['secret_store_ref'])
            self.assertIsNone(secret_data.get('id'))
            self.assertIsNone(secret_data.get('secret_store_id'))
            self.assertIsNotNone(secret_data['name'])
            self.assertIsNotNone(secret_data['secret_store_plugin'])
            self.assertIsNotNone(secret_data['created'])
            self.assertIsNotNone(secret_data['updated'])
            self.assertEqual(models.States.ACTIVE, secret_data['status'])

    def test_get_all_secret_stores_when_multiple_backends_not_enabled(self):

        self._init_multiple_backends(enabled=False)

        resp = self.app.get('/secret-stores', expect_errors=True)
        self.assertEqual(404, resp.status_int)

        resp = self.app.get('/secret-stores/any_valid_id',
                            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_all_secret_stores_with_unsupported_http_method(self):

        self._init_multiple_backends()

        resp = self.app.put('/secret-stores', expect_errors=True)
        self.assertEqual(405, resp.status_int)

        resp = self.app.patch('/secret-stores', expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_get_global_default(self):

        self._init_multiple_backends(global_default_index=1)

        resp = self.app.get('/secret-stores/global-default',
                            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        resp_data = resp.json
        self.assertTrue(resp_data['global_default'])
        self.assertIn('kmip', resp_data['name'].lower())
        self.assertIsNotNone(resp_data['secret_store_ref'])
        self.assertIsNotNone(resp_data['secret_store_plugin'])
        self.assertIsNone(resp_data['crypto_plugin'])
        self.assertIsNotNone(resp_data['created'])
        self.assertIsNotNone(resp_data['updated'])
        self.assertEqual(models.States.ACTIVE, resp_data['status'])

    def test_get_global_default_when_multiple_backends_not_enabled(self):

        self._init_multiple_backends(enabled=False)

        with mock.patch('barbican.common.resources.'
                        'get_or_create_project') as m1:

            resp = self.app.get('/secret-stores/global-default',
                                expect_errors=True)

            self.assertFalse(m1.called)
            self.assertEqual(404, resp.status_int)

    def test_get_preferred_when_preferred_is_set(self):
        self._init_multiple_backends(global_default_index=1)

        secret_stores = self.secret_store_repo.get_all()
        project1 = self._create_project()

        self._create_project_store(project1.id, secret_stores[0].id)

        self.app.extra_environ = {
            'barbican.context': self._build_context(project1.external_id)
        }
        resp = self.app.get('/secret-stores/preferred',
                            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        resp_data = resp.json
        self.assertEqual(secret_stores[0].name, resp_data['name'])
        self.assertEqual(secret_stores[0].global_default,
                         resp_data['global_default'])
        self.assertIn('/secret-stores/{0}'.format(secret_stores[0].id),
                      resp_data['secret_store_ref'])
        self.assertIsNotNone(resp_data['created'])
        self.assertIsNotNone(resp_data['updated'])
        self.assertEqual(models.States.ACTIVE, resp_data['status'])

    def test_get_preferred_when_preferred_is_not_set(self):
        self._init_multiple_backends(global_default_index=1)
        project1 = self._create_project()

        self.app.extra_environ = {
            'barbican.context': self._build_context(project1.external_id)
        }
        resp = self.app.get('/secret-stores/preferred',
                            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_preferred_when_multiple_backends_not_enabled(self):

        self._init_multiple_backends(enabled=False)

        with mock.patch('barbican.common.resources.'
                        'get_or_create_project') as m1:

            resp = self.app.get('/secret-stores/preferred',
                                expect_errors=True)

            self.assertFalse(m1.called)
            self.assertEqual(404, resp.status_int)


class WhenTestingSecretStore(utils.BarbicanAPIBaseTestCase,
                             SecretStoresMixin):

    def setUp(self):
        super(WhenTestingSecretStore, self).setUp()
        self.secret_store_repo = repos.get_secret_stores_repository()

    def test_get_a_secret_store_when_no_error(self):

        self._init_multiple_backends()

        secret_stores = self.secret_store_repo.get_all()

        store = secret_stores[0]

        resp = self.app.get('/secret-stores/{0}'.format(store.id),
                            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        data = resp.json
        self.assertEqual(store.global_default, data['global_default'])
        self.assertEqual(store.name, data['name'])
        self.assertIn('/secret-stores/{0}'.format(store.id),
                      data['secret_store_ref'])
        self.assertIsNotNone(data['secret_store_plugin'])
        self.assertIsNotNone(data['created'])
        self.assertIsNotNone(data['updated'])
        self.assertEqual(models.States.ACTIVE, data['status'])

    def test_invalid_uri_for_secret_stores_subresource(self):
        self._init_multiple_backends()

        resp = self.app.get('/secret-stores/invalid_uri',
                            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_a_secret_store_with_unsupported_http_method(self):
        self._init_multiple_backends()

        secret_stores = self.secret_store_repo.get_all()
        store_id = secret_stores[0].id

        resp = self.app.put('/secret-stores/{0}'.format(store_id),
                            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_invalid_uri_for_a_secret_store_subresource(self):
        self._init_multiple_backends()

        secret_stores = self.secret_store_repo.get_all()
        resp = self.app.get('/secret-stores/{0}/invalid_uri'.
                            format(secret_stores[0].id), expect_errors=True)
        self.assertEqual(405, resp.status_int)


class WhenTestingProjectSecretStore(utils.BarbicanAPIBaseTestCase,
                                    SecretStoresMixin):

    def setUp(self):
        super(WhenTestingProjectSecretStore, self).setUp()
        self.secret_store_repo = repos.get_secret_stores_repository()
        self.proj_store_repo = repos.get_project_secret_store_repository()

    def test_set_a_preferred_secret_store_when_no_error(self):

        self._init_multiple_backends()

        stores = self.secret_store_repo.get_all()

        proj_external_id = uuidutils.generate_uuid(dashed=False)
        # get ids as secret store are not bound to session after a rest call.
        store_ids = [store.id for store in stores]
        for store_id in store_ids:
            self.app.extra_environ = {
                'barbican.context': self._build_context(proj_external_id)
            }
            resp = self.app.post('/secret-stores/{0}/preferred'.
                                 format(store_id), expect_errors=False)
            self.assertEqual(204, resp.status_int)

            # Now make sure preferred store is set to store id via get call
            resp = self.app.get('/secret-stores/preferred')
            self.assertIn(store_id, resp.json['secret_store_ref'])

    def test_unset_a_preferred_secret_store_when_no_error(self):

        self._init_multiple_backends()

        stores = self.secret_store_repo.get_all()

        proj_external_id = uuidutils.generate_uuid(dashed=False)
        # get ids as secret store are not bound to session after a rest call.
        store_ids = [store.id for store in stores]
        for store_id in store_ids:
            self.app.extra_environ = {
                'barbican.context': self._build_context(proj_external_id)
            }
            resp = self.app.post('/secret-stores/{0}/preferred'.
                                 format(store_id), expect_errors=False)
            self.assertEqual(204, resp.status_int)

            # unset preferred store here
            resp = self.app.delete('/secret-stores/{0}/preferred'.
                                   format(store_id), expect_errors=False)
            self.assertEqual(204, resp.status_int)

            # Now make sure that there is no longer a preferred store set
            resp = self.app.get('/secret-stores/preferred',
                                expect_errors=True)
            self.assertEqual(404, resp.status_int)

    def test_unset_a_preferred_store_when_not_found_error(self):
        self._init_multiple_backends()

        stores = self.secret_store_repo.get_all()
        proj_external_id = uuidutils.generate_uuid(dashed=False)
        self.app.extra_environ = {
            'barbican.context': self._build_context(proj_external_id)
        }
        resp = self.app.delete('/secret-stores/{0}/preferred'.
                               format(stores[0].id), expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_preferred_secret_store_call_with_unsupported_http_method(self):
        self._init_multiple_backends()

        secret_stores = self.secret_store_repo.get_all()
        store_id = secret_stores[0].id

        proj_external_id = uuidutils.generate_uuid(dashed=False)

        self.app.extra_environ = {
            'barbican.context': self._build_context(proj_external_id)
        }
        resp = self.app.put('/secret-stores/{0}/preferred'.
                            format(store_id), expect_errors=True)

        self.assertEqual(405, resp.status_int)
