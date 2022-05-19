# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from oslo_utils import uuidutils

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingSecretStoresRepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingSecretStoresRepo, self).setUp()
        self.s_stores_repo = repositories.get_secret_stores_repository()
        self.def_name = "PKCS11 HSM"
        self.def_store_plugin = "store_crypto"
        self.def_crypto_plugin = "p11_crypto"
        self.default_secret_store = self._create_secret_store(
            self.def_name, self.def_store_plugin, self.def_crypto_plugin, True)

    def _create_secret_store(self, name, store_plugin, crypto_plugin=None,
                             global_default=None):
        session = self.s_stores_repo.get_session()

        s_stores_model = models.SecretStores(name=name,
                                             store_plugin=store_plugin,
                                             crypto_plugin=crypto_plugin,
                                             global_default=global_default)
        s_stores = self.s_stores_repo.create_from(s_stores_model,
                                                  session=session)

        s_stores.save(session=session)

        session.commit()
        return s_stores

    def test_get_by_entity_id(self):

        session = self.s_stores_repo.get_session()
        s_stores = self.s_stores_repo.get(self.default_secret_store.id,
                                          session=session)

        self.assertIsNotNone(s_stores)
        self.assertEqual(self.def_store_plugin, s_stores.store_plugin)
        self.assertEqual(self.def_crypto_plugin, s_stores.crypto_plugin)
        self.assertTrue(s_stores.global_default)
        self.assertEqual(models.States.ACTIVE, s_stores.status)

    def test_should_raise_notfound_exception_get_by_entity_id(self):
        self.assertRaises(exception.NotFound, self.s_stores_repo.get,
                          "invalid_id", suppress_exception=False)

    def test_delete_entity_by_id(self):

        session = self.s_stores_repo.get_session()
        s_stores = self.s_stores_repo.get(self.default_secret_store.id,
                                          session=session)
        self.assertIsNotNone(s_stores)

        self.s_stores_repo.delete_entity_by_id(self.default_secret_store.id,
                                               None, session=session)
        s_stores = self.s_stores_repo.get(self.default_secret_store.id,
                                          suppress_exception=True,
                                          session=session)

        self.assertIsNone(s_stores)

    def test_get_all(self):

        session = self.s_stores_repo.get_session()
        all_stores = self.s_stores_repo.get_all(session=session)

        self.assertIsNotNone(all_stores)
        self.assertEqual(1, len(all_stores))

        self._create_secret_store("db backend", "store_crypto",
                                  "simple_crypto", False)
        all_stores = self.s_stores_repo.get_all(session=session)
        self.assertEqual(2, len(all_stores))

        self.assertEqual("simple_crypto", all_stores[1].crypto_plugin)
        self.assertEqual("store_crypto", all_stores[1].store_plugin)
        self.assertEqual("db backend", all_stores[1].name)
        self.assertEqual(False, all_stores[1].global_default)

    def test_no_data_case_for_get_all(self):

        self.s_stores_repo.delete_entity_by_id(self.default_secret_store.id,
                                               None)
        session = self.s_stores_repo.get_session()
        all_stores = self.s_stores_repo.get_all(session=session)
        self.assertEqual([], all_stores)

    def test_get_all_check_sorting_order(self):
        """Check that all stores are sorted in ascending creation time

        """
        session = self.s_stores_repo.get_session()

        self._create_secret_store("second_name", "second_store",
                                  "second_crypto", False)
        m_stores = self._create_secret_store("middle_name", "middle_store",
                                             "middle_crypto", False)
        self._create_secret_store("last_name", "last_store", "last_crypto",
                                  False)

        all_stores = self.s_stores_repo.get_all(session=session)
        self.assertIsNotNone(all_stores)
        self.assertEqual(4, len(all_stores))
        # returned list is sorted by created_at field so check for last entry
        self.assertEqual("last_crypto", all_stores[3].crypto_plugin)
        self.assertEqual("last_store", all_stores[3].store_plugin)
        self.assertEqual("last_name", all_stores[3].name)
        self.assertEqual(False, all_stores[3].global_default)

        # Now delete in between entry and create as new entry
        self.s_stores_repo.delete_entity_by_id(m_stores.id, None,
                                               session=session)
        all_stores = self.s_stores_repo.get_all(session=session)

        self._create_secret_store("middle_name", "middle_store",
                                  "middle_crypto", False)
        all_stores = self.s_stores_repo.get_all(session=session)
        # now newly created entry should be last one.
        self.assertEqual("middle_crypto", all_stores[3].crypto_plugin)
        self.assertEqual("middle_store", all_stores[3].store_plugin)
        self.assertEqual("middle_name", all_stores[3].name)
        self.assertEqual(False, all_stores[3].global_default)

    def test_should_raise_constraint_for_same_plugin_names(self):
        """Check for store and crypto plugin name combination uniqueness"""

        name = 'second_name'
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        self._create_secret_store(name, store_plugin, crypto_plugin, False)
        self.assertRaises(exception.ConstraintCheck, self._create_secret_store,
                          "thrid_name", store_plugin, crypto_plugin, False)

    def test_should_raise_constraint_for_same_names(self):
        """Check for secret store 'name' uniqueness"""

        name = 'Db backend'
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        self._create_secret_store(name, store_plugin, crypto_plugin, False)
        self.assertRaises(exception.ConstraintCheck, self._create_secret_store,
                          name, "another_store", "another_crypto", False)

    def test_do_entity_name(self):
        """Code coverage for entity_name which is used in case of exception.

        Raising duplicate error for store and crypto plugin combination
        """
        name = "DB backend"
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        self._create_secret_store(name, store_plugin, crypto_plugin, False)
        try:
            self._create_secret_store(name, store_plugin, crypto_plugin, False)
            self.assertFail()
        except exception.ConstraintCheck as ex:
            self.assertIn("SQL constraint check failed", str(ex))


class WhenTestingProjectSecretStoreRepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingProjectSecretStoreRepo, self).setUp()
        self.proj_store_repo = repositories.\
            get_project_secret_store_repository()
        self.def_name = "PKCS11 HSM"
        self.def_store_plugin = "store_crypto"
        self.def_crypto_plugin = "p11_crypto"
        self.default_secret_store = self._create_secret_store(
            self.def_name, self.def_store_plugin, self.def_crypto_plugin, True)

    def _create_secret_store(self, name, store_plugin, crypto_plugin=None,
                             global_default=None):
        s_stores_repo = repositories.get_secret_stores_repository()
        session = s_stores_repo.get_session()

        s_stores_model = models.SecretStores(name=name,
                                             store_plugin=store_plugin,
                                             crypto_plugin=crypto_plugin,
                                             global_default=global_default)
        s_stores = s_stores_repo.create_from(s_stores_model,
                                             session=session)
        s_stores.save(session=session)

        session.commit()
        return s_stores

    def _create_project(self):
        session = self.proj_store_repo.get_session()

        project = models.Project()
        project.external_id = ("keystone_project_id" +
                               uuidutils.generate_uuid(dashed=False))
        project.save(session=session)
        return project

    def _create_project_store(self, project_id, secret_store_id):
        session = self.proj_store_repo.get_session()

        proj_model = models.ProjectSecretStore(project_id, secret_store_id)

        proj_s_store = self.proj_store_repo.create_from(proj_model, session)
        proj_s_store.save(session=session)
        return proj_s_store

    def test_get_by_entity_id(self):
        """Tests for 'get' call by project secret store id"""

        project = self._create_project()

        proj_s_store = self._create_project_store(project.id,
                                                  self.default_secret_store.id)

        session = self.proj_store_repo.get_session()
        s_stores = self.proj_store_repo.get(proj_s_store.id, session=session)

        self.assertIsNotNone(proj_s_store)
        self.assertEqual(project.id, proj_s_store.project_id)
        self.assertEqual(self.default_secret_store.id,
                         proj_s_store.secret_store_id)
        self.assertEqual(models.States.ACTIVE, s_stores.status)
        # assert values via relationship
        self.assertEqual(self.default_secret_store.store_plugin,
                         proj_s_store.secret_store.store_plugin)
        self.assertEqual(project.external_id, proj_s_store.project.external_id)

    def test_should_raise_notfound_exception_get_by_entity_id(self):
        self.assertRaises(exception.NotFound, self.proj_store_repo.get,
                          "invalid_id", suppress_exception=False)

    def test_delete_entity_by_id(self):

        project = self._create_project()

        proj_s_store = self._create_project_store(project.id,
                                                  self.default_secret_store.id)

        session = self.proj_store_repo.get_session()
        proj_s_store = self.proj_store_repo.get(proj_s_store.id,
                                                session=session)

        self.assertIsNotNone(proj_s_store)

        self.proj_store_repo.delete_entity_by_id(proj_s_store.id, None,
                                                 session=session)
        proj_s_store = self.proj_store_repo.get(proj_s_store.id,
                                                suppress_exception=True,
                                                session=session)

        self.assertIsNone(proj_s_store)

    def test_should_raise_constraint_for_same_project_id(self):
        """Check preferred secret store is set only once for project"""

        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        s_store1 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        # set preferred secret store for project1
        self._create_project_store(project1.id,
                                   s_store1.id)

        name = "second_name"
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        s_store2 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        self.assertRaises(exception.ConstraintCheck,
                          self._create_project_store,
                          project1.id, s_store2.id)

    def test_do_entity_name(self):
        """Code coverage for entity_name which is used in case of exception.

        Raising duplicate error when try to set another entry for existing
        project
        """
        project1 = self._create_project()
        name = "first name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        s_store1 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        # set preferred secret store for project1
        self._create_project_store(project1.id,
                                   s_store1.id)
        try:
            name = "second_name"
            store_plugin = 'second_store'
            crypto_plugin = 'second_crypto'
            s_store2 = self._create_secret_store(name, store_plugin,
                                                 crypto_plugin, False)
            self._create_project_store(project1.id, s_store2.id)
            self.assertFail()
        except exception.ConstraintCheck as ex:
            self.assertIn("SQL constraint check failed", str(ex))

    def test_get_secret_store_for_project(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        s_store1 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        # set preferred secret store for project1
        proj_s_store = self._create_project_store(project1.id, s_store1.id)

        # get preferred secret store by barbican project id
        read_project_s_store = self.proj_store_repo.\
            get_secret_store_for_project(project1.id, None)

        self.assertEqual(proj_s_store.project_id,
                         read_project_s_store.project_id)
        self.assertEqual(proj_s_store.secret_store_id,
                         read_project_s_store.secret_store_id)

        # get preferred secret store by keystone project id
        read_project_s_store = self.proj_store_repo.\
            get_secret_store_for_project(None, project1.external_id)

        self.assertEqual(proj_s_store.project_id,
                         read_project_s_store.project_id)
        self.assertEqual(project1.external_id,
                         read_project_s_store.project.external_id)

        self.assertEqual(proj_s_store.secret_store_id,
                         read_project_s_store.secret_store_id)

    def test_raise_notfound_exception_get_secret_store_for_project(self):
        self.assertRaises(exception.NotFound,
                          self.proj_store_repo.get_secret_store_for_project,
                          "invalid_id", None, suppress_exception=False)

    def test_with_exception_suppressed_get_secret_store_for_project(self):
        returned_value = self.proj_store_repo.\
            get_secret_store_for_project("invalid_id", None,
                                         suppress_exception=True)
        self.assertIsNone(returned_value)

    def test_get_project_entities(self):
        entities = self.proj_store_repo.get_project_entities(
            uuidutils.generate_uuid(dashed=False))
        self.assertEqual([], entities)

    def test_create_or_update_for_project(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        s_store1 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        # assert that no preferred secret store is set project.
        entity = self.proj_store_repo.get_secret_store_for_project(
            project1.id, None, suppress_exception=True)
        self.assertIsNone(entity)

        # create/set preferred secret store now
        created_entity = self.proj_store_repo.create_or_update_for_project(
            project1.id, s_store1.id)

        entity = self.proj_store_repo.get_secret_store_for_project(
            project1.id, None, suppress_exception=False)
        self.assertIsNotNone(entity)  # new preferred secret store

        self.assertEqual(project1.id, entity.project_id)
        self.assertEqual(s_store1.id, entity.secret_store_id)
        self.assertEqual(store_plugin, entity.secret_store.store_plugin)
        self.assertEqual(crypto_plugin, entity.secret_store.crypto_plugin)
        self.assertEqual(name, entity.secret_store.name)

        name = 'second_name'
        store_plugin = 'second_store'
        crypto_plugin = 'second_crypto'
        s_store2 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        updated_entity = self.proj_store_repo.create_or_update_for_project(
            project1.id, s_store2.id)

        self.assertEqual(created_entity.id, updated_entity.id)
        self.assertEqual(s_store2.id, updated_entity.secret_store_id)

    def test_get_count_by_secret_store(self):
        project1 = self._create_project()
        name = "first_name"
        store_plugin = 'first_store'
        crypto_plugin = 'first_crypto'
        s_store1 = self._create_secret_store(name, store_plugin,
                                             crypto_plugin, False)

        count = self.proj_store_repo.get_count_by_secret_store(s_store1.id)
        self.assertEqual(0, count)

        # create/set preferred secret store now
        self.proj_store_repo.create_or_update_for_project(project1.id,
                                                          s_store1.id)

        count = self.proj_store_repo.get_count_by_secret_store(s_store1.id)
        self.assertEqual(1, count)

        project2 = self._create_project()
        self.proj_store_repo.create_or_update_for_project(project2.id,
                                                          s_store1.id)

        count = self.proj_store_repo.get_count_by_secret_store(s_store1.id)
        self.assertEqual(2, count)
