#    Copyright 2018 Fujitsu.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_utils import uuidutils

from barbican.common import exception
from barbican import objects
from barbican.tests.objects import test_ovo_base


class TestProjectSecretStore(test_ovo_base.OVOTestCase):
    def setUp(self):
        super(TestProjectSecretStore, self).setUp()
        self.init()

    def init(self):
        self.def_name = "PKCS11 HSM"
        self.def_store_plugin = "store_crypto"
        self.def_crypto_plugin = "p11_crypto"
        self.default_secret_stores = self._create_secret_store_obj(
            self.def_name, self.def_store_plugin, self.def_crypto_plugin, True)

    def _create_secret_store_obj(self, name, store_plugin, crypto_plugin=None,
                                 global_default=None):
        secret_stores_obj = objects.SecretStores(name=name,
                                                 store_plugin=store_plugin,
                                                 crypto_plugin=crypto_plugin,
                                                 global_default=global_default)
        secret_stores_obj.create(session=self.session)
        return secret_stores_obj

    def _create_project(self):
        external_id = 'keystone_project_id' + uuidutils.generate_uuid(
            dashed=True)
        project = objects.Project(external_id=external_id)
        project.create(session=self.session)
        return project

    def _create_project_secret_store(self, project_id, secret_store_id):
        project_secret_store = objects.ProjectSecretStore(
            project_id=project_id,
            secret_store_id=secret_store_id)
        project_secret_store.create(session=self.session)
        return project_secret_store

    def test_ovo_create_by_entity_id(self):
        """Tests for 'create' call by project secret store id"""

        project = self._create_project()

        project_secret_store = self._create_project_secret_store(
            project.id, self.default_secret_stores.id)

        self.assertIsNotNone(project_secret_store)
        self.assertEqual(project.id, project_secret_store.project_id)
        self.assertEqual(self.default_secret_stores.id,
                         project_secret_store.secret_store_id)
        self.assertEqual(objects.States.ACTIVE, project_secret_store.status)
        # assert values via relationship
        self.assertEqual(self.default_secret_stores.store_plugin,
                         project_secret_store.secret_store.store_plugin)
        self.assertEqual(project.external_id,
                         project_secret_store.project.external_id)

    def test_ovo_should_raise_notfound_exception_get_by_entity_id(self):
        self.assertRaises(exception.NotFound, objects.ProjectSecretStore.get,
                          "invalid_id", suppress_exception=False)

    def test_ovo_delete_entity_by_id(self):

        project = self._create_project()

        project_secret_store = self._create_project_secret_store(
            project.id, self.default_secret_stores.id)

        project_secret_store = objects.ProjectSecretStore.get(
            project_secret_store.id, session=self.session)

        self.assertIsNotNone(project_secret_store)

        objects.ProjectSecretStore.delete_entity_by_id(
            project_secret_store.id, None, session=self.session)
        project_secret_store = objects.ProjectSecretStore.get(
            project_secret_store.id,
            suppress_exception=True,
            session=self.session)

        self.assertIsNone(project_secret_store)

    def test_ovo_should_raise_constraint_for_same_project_id(self):
        """Check preferred secret store is set only once for project"""

        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        secret_stores1 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        # set preferred secret store for project1
        self._create_project_secret_store(project1.id,
                                          secret_stores1.id)

        name = "second_name"
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        secret_stores2 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        self.assertRaises(exception.ConstraintCheck,
                          self._create_project_secret_store,
                          project1.id, secret_stores2.id)

    def test_ovo_do_entity_name(self):
        """Code coverage for entity_name which is used in case of exception.

        Raising duplicate error when try to set another entry for existing
        project
        """
        project1 = self._create_project()
        name = "first name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        secret_stores1 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        # set preferred secret store for project1
        self._create_project_secret_store(project1.id,
                                          secret_stores1.id)
        try:
            name = "second_name"
            store_plugin = 'second_store'
            crypto_plugin = 'second_crypto'
            secret_stores2 = self._create_secret_store_obj(name,
                                                           store_plugin,
                                                           crypto_plugin,
                                                           False)
            self._create_project_secret_store(project1.id, secret_stores2.id)
            self.assertFail()
        except exception.ConstraintCheck as ex:
            self.assertIn("SQL constraint check failed", str(ex))

    def test_ovo_get_secret_store_for_project(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        secret_stores1 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        # set preferred secret store for project1
        project_secret_store = self._create_project_secret_store(
            project1.id, secret_stores1.id)

        # get preferred secret store by barbican project id
        read_project_secret_stores = objects.ProjectSecretStore.\
            get_secret_store_for_project(project1.id, None,
                                         session=self.session)

        self.assertEqual(project_secret_store.project_id,
                         read_project_secret_stores.project_id)
        self.assertEqual(project_secret_store.secret_store_id,
                         read_project_secret_stores.secret_store_id)

        # get preferred secret store by keystone project id
        read_project_secret_stores = objects.ProjectSecretStore. \
            get_secret_store_for_project(None, project1.external_id,
                                         session=self.session)

        self.assertEqual(project_secret_store.project_id,
                         read_project_secret_stores.project_id)
        self.assertEqual(project1.external_id,
                         read_project_secret_stores.project.external_id)

        self.assertEqual(project_secret_store.secret_store_id,
                         read_project_secret_stores.secret_store_id)

    def test_ovo_raise_notfound_exception_get_secret_store_for_project(self):
        self.assertRaises(
            exception.NotFound,
            objects.ProjectSecretStore.get_secret_store_for_project,
            "invalid_id", None, suppress_exception=False)

    def test_ovo_with_exception_suppressed_get_secret_store_for_project(self):
        returned_value = objects.ProjectSecretStore. \
            get_secret_store_for_project("invalid_id", None,
                                         suppress_exception=True,
                                         session=self.session)
        self.assertIsNone(returned_value)

    def test_ovo_get_project_entities(self):
        entities = objects.ProjectSecretStore.get_project_entities(
            uuidutils.generate_uuid(dashed=False), session=self.session)
        self.assertEqual([], entities)

    def test_ovo_create_or_update_for_project(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        secret_stores1 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        # assert that no preferred secret store is set project.
        entity = objects.ProjectSecretStore.get_secret_store_for_project(
            project1.id, None, suppress_exception=True, session=self.session)
        self.assertIsNone(entity)

        # create/set preferred secret store now
        created_entity = \
            objects.ProjectSecretStore.create_or_update_for_project(
                project1.id, secret_stores1.id, session=self.session)

        entity = objects.ProjectSecretStore.get_secret_store_for_project(
            project1.id, None, suppress_exception=False, session=self.session)
        self.assertIsNotNone(entity)  # new preferred secret store

        self.assertEqual(project1.id, entity.project_id)
        self.assertEqual(secret_stores1.id, entity.secret_store_id)
        self.assertEqual(store_plugin, entity.secret_store.store_plugin)
        self.assertEqual(crypto_plugin, entity.secret_store.crypto_plugin)
        self.assertEqual(name, entity.secret_store.name)

        name = 'second_name'
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        secret_stores2 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        updated_entity = \
            objects.ProjectSecretStore.create_or_update_for_project(
                project1.id, secret_stores2.id, session=self.session)

        self.assertEqual(created_entity.id, updated_entity.id)
        self.assertEqual(secret_stores2.id, updated_entity.secret_store_id)

    def test_ovo_get_count_by_secret_store(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        secret_stores1 = self._create_secret_store_obj(name, store_plugin,
                                                       crypto_plugin, False)

        count = objects.ProjectSecretStore.get_count_by_secret_store(
            secret_stores1.id, session=self.session)
        self.assertEqual(0, count)

        # create/set preferred secret store now
        objects.ProjectSecretStore.create_or_update_for_project(
            project1.id, secret_stores1.id, session=self.session)

        count = objects.ProjectSecretStore.get_count_by_secret_store(
            secret_stores1.id, session=self.session)
        self.assertEqual(1, count)

        project2 = self._create_project()
        objects.ProjectSecretStore.create_or_update_for_project(
            project2.id, secret_stores1.id, session=self.session)

        count = objects.ProjectSecretStore.get_count_by_secret_store(
            secret_stores1.id, session=self.session)
        self.assertEqual(2, count)

    def test_ovo_should_throw_exception_missing_project_id(self):
        project_secret_store_1 = objects.ProjectSecretStore(
            project_id=None, secret_store_id='ss_123456')
        project_secret_store_2 = objects.ProjectSecretStore(
            project_id='', secret_store_id='ss_123456')
        self.assertRaises(exception.MissingArgumentError,
                          project_secret_store_1.create, session=self.session)
        self.assertRaises(exception.MissingArgumentError,
                          project_secret_store_2.create, session=self.session)

    def test_ovo_should_throw_exception_missing_secret_store_id(self):
        project_secret_store_1 = objects.ProjectSecretStore(
            project_id='proj_123456', secret_store_id=None)
        project_secret_store_2 = objects.ProjectSecretStore(
            project_id='proj_123456', secret_store_id='')

        self.assertRaises(exception.MissingArgumentError,
                          project_secret_store_1.create, session=self.session)
        self.assertRaises(exception.MissingArgumentError,
                          project_secret_store_2.create, session=self.session)
