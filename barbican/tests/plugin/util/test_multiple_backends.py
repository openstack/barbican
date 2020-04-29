# (c) Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

import collections
from unittest import mock

from oslo_utils import uuidutils

from barbican.common import config
from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.crypto import base
from barbican.plugin.crypto import manager as cm
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto import simple_crypto
from barbican.plugin.interface import secret_store
from barbican.plugin import kmip_secret_store as kss
from barbican.plugin import store_crypto
from barbican.plugin.util import multiple_backends
from barbican.tests import utils as test_utils


class MockedManager(object):

    NAME_PREFIX = "friendly_"

    def __init__(self, names, enabled=True,
                 plugin_lookup_field='store_plugin'):
        ExtTuple = collections.namedtuple('ExtTuple', ['name', 'obj'])
        self.extensions = []
        for name in names:
            m = mock.MagicMock()
            m.get_plugin_name.return_value = self.NAME_PREFIX + name
            new_extension = ExtTuple(name, m)
            self.extensions.append(new_extension)
        self.global_default_store_dict = None
        self.parsed_stores = multiple_backends.read_multiple_backends_config()


class WhenReadingMultipleBackendsConfig(test_utils.MultipleBackendsTestCase):

    def test_successful_conf_read(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True,
                                global_default_index=1)

        stores = multiple_backends.read_multiple_backends_config()

        self.assertEqual(len(ss_plugins), len(stores))
        self.assertEqual('ss_p1', stores[0].store_plugin)
        self.assertEqual('cr_p1', stores[0].crypto_plugin)
        self.assertEqual(False, stores[0].global_default)
        self.assertEqual('ss_p2', stores[1].store_plugin)
        self.assertEqual('cr_p2', stores[1].crypto_plugin)
        self.assertTrue(stores[1].global_default)
        self.assertEqual('ss_p3', stores[2].store_plugin)
        self.assertEqual('cr_p3', stores[2].crypto_plugin)
        self.assertEqual(False, stores[2].global_default)

    def test_fail_when_store_plugin_name_missing(self):
        ss_plugins = ['ss_p1', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)

        self.assertRaises(exception.MultipleStorePluginValueMissing,
                          multiple_backends.read_multiple_backends_config)

    def test_fail_when_store_plugin_name_is_blank(self):
        ss_plugins = ['ss_p1', '', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)

        self.assertRaises(exception.MultipleStorePluginValueMissing,
                          multiple_backends.read_multiple_backends_config)

    def test_successful_conf_read_when_crypto_plugin_name_is_missing(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)

        stores = multiple_backends.read_multiple_backends_config()
        self.assertEqual(len(ss_plugins), len(stores))

    def test_conf_read_when_multiple_plugin_disabled(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=False)

        stores = multiple_backends.read_multiple_backends_config()
        self.assertIsNone(stores)

    def test_successful_conf_read_when_crypto_plugin_name_is_blank(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', '', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)

        stores = multiple_backends.read_multiple_backends_config()
        self.assertEqual(len(ss_plugins), len(stores))
        self.assertEqual('', stores[1].crypto_plugin)

    def test_fail_when_global_default_not_specified(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True,
                                global_default_index=-1)

        self.assertRaises(exception.MultipleStoreIncorrectGlobalDefault,
                          multiple_backends.read_multiple_backends_config)

    def test_fail_when_stores_lookup_suffix_missing_when_enabled(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True,
                                global_default_index=0)

        conf = config.get_module_config('secretstore')
        conf.set_override("stores_lookup_suffix", [], group='secretstore')
        self.assertRaises(exception.MultipleSecretStoreLookupFailed,
                          multiple_backends.read_multiple_backends_config)

    def test_fail_when_secretstore_section_missing(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True,
                                global_default_index=-1)
        ss_conf = config.get_module_config('secretstore')

        existing_value = ss_conf.secretstore.stores_lookup_suffix
        existing_value.append('unknown_section')

        ss_conf.set_override('stores_lookup_suffix', existing_value,
                             'secretstore')

        self.assertRaises(exception.MultipleStorePluginValueMissing,
                          multiple_backends.read_multiple_backends_config)


class WhenInvokingSyncSecretStores(test_utils.MultipleBackendsTestCase):

    def setUp(self):
        super(WhenInvokingSyncSecretStores, self).setUp()

    def test_successful_syncup_no_existing_secret_stores(self):

        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3', 'ss_p4', 'ss_p5']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3', 'cr_p4', 'cr_p5']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        default_secret_store = multiple_backends.\
            get_global_default_secret_store()
        self.assertEqual('ss_p1', default_secret_store.store_plugin)
        self.assertEqual('cr_p1', default_secret_store.crypto_plugin)
        self.assertEqual(MockedManager.NAME_PREFIX + 'cr_p1',
                         default_secret_store.name)

        ss_db_entries = repositories.get_secret_stores_repository().get_all()
        self.assertEqual(5, len(ss_db_entries))

    def test_syncup_with_existing_secret_stores(self):

        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3', 'ss_p4', 'ss_p5']
        cr_plugins = ['cr_p1', '', 'cr_p3', 'cr_p4', 'cr_p5']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        ss_db_entries = repositories.get_secret_stores_repository().get_all()
        self.assertEqual(5, len(ss_db_entries))

        # check friendly name for the case when crypto plugin is not there
        ss_db_entry = self._get_secret_store_entry('ss_p2', None)
        self.assertIsNotNone(ss_db_entry)
        self.assertEqual(MockedManager.NAME_PREFIX + 'ss_p2',
                         ss_db_entry.name)

        ss_plugins = ['ss_p3', 'ss_p4', 'ss_p5', 'ss_p6']
        cr_plugins = ['cr_p3', 'cr_p4', 'cr_p5', 'cr_p6']
        # update conf and re-run sync store
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)

        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        ss_db_entry = self._get_secret_store_entry('ss_p2', 'cr_p2')
        self.assertIsNone(ss_db_entry)

        ss_db_entry = self._get_secret_store_entry('ss_p6', 'cr_p6')
        self.assertIsNotNone(ss_db_entry)

        default_secret_store = multiple_backends.\
            get_global_default_secret_store()
        self.assertEqual('ss_p3', default_secret_store.store_plugin)
        self.assertEqual('cr_p3', default_secret_store.crypto_plugin)
        self.assertEqual(MockedManager.NAME_PREFIX + 'cr_p3',
                         default_secret_store.name)
        ss_db_entries = repositories.get_secret_stores_repository().get_all()
        self.assertEqual(4, len(ss_db_entries))

    def test_syncup_modify_global_default(self):

        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3', 'ss_p4', 'ss_p5']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3', 'cr_p4', 'cr_p5']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        global_secret_store = multiple_backends.\
            get_global_default_secret_store()
        self.assertEqual('ss_p1', global_secret_store.store_plugin)
        self.assertEqual('cr_p1', global_secret_store.crypto_plugin)
        self.assertEqual(MockedManager.NAME_PREFIX + 'cr_p1',
                         global_secret_store.name)

        ss_plugins = ['ss_p9', 'ss_p4', 'ss_p5']
        cr_plugins = ['cr_p9', 'cr_p4', 'cr_p5']
        # update conf and re-run sync store
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        global_secret_store = multiple_backends.\
            get_global_default_secret_store()
        self.assertEqual('ss_p9', global_secret_store.store_plugin)
        self.assertEqual('cr_p9', global_secret_store.crypto_plugin)
        self.assertEqual(MockedManager.NAME_PREFIX + 'cr_p9',
                         global_secret_store.name)

    def test_syncup_with_store_and_crypto_plugins_count_mismatch(self):

        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3', 'ss_p4']
        cr_plugins = ['cr_p1', '', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        # empty crypto_plugin name maps to None in database entry
        ss_db_entry = self._get_secret_store_entry('ss_p2', None)
        self.assertIsNotNone(ss_db_entry)
        ss_db_entry = self._get_secret_store_entry('ss_p2', '')
        self.assertIsNone(ss_db_entry)

        # missing crypto plugin name maps to None in database entry
        ss_db_entry = self._get_secret_store_entry('ss_p4', None)
        self.assertIsNotNone(ss_db_entry)

    def test_syncup_delete_secret_store_with_preferred_project_using_it(self):
        """Removing secret store will fail if its defined as preferred store.

        """
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3', 'ss_p4']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3', 'cr_p4']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        secretstore_manager = MockedManager(ss_plugins)
        crypto_manager = MockedManager(cr_plugins)
        multiple_backends.sync_secret_stores(secretstore_manager,
                                             crypto_manager)

        with mock.patch('barbican.model.repositories.'
                        'get_project_secret_store_repository') as ps_repo:
            # Mocking with 2 projects as using preferred secret store
            ps_repo.get_count_by_secret_store.return_value = 2

            ss_plugins = ['ss_p3', 'ss_p4']
            cr_plugins = ['cr_p3', 'cr_p4']
            self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
            secretstore_manager = MockedManager(ss_plugins)
            crypto_manager = MockedManager(cr_plugins)

            self.assertRaises(exception.MultipleStorePluginStillInUse,
                              multiple_backends.sync_secret_stores,
                              secretstore_manager, crypto_manager)

    def test_get_global_default_store_when_multiple_backends_disabled(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=False)

        default_store = multiple_backends.get_global_default_secret_store()
        self.assertIsNone(default_store)


class TestGetApplicablePlugins(test_utils.MultipleBackendsTestCase):

    def setUp(self):
        super(TestGetApplicablePlugins, self).setUp()

    def test_get_when_project_preferred_plugin_is_set(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        ss_manager = MockedManager(ss_plugins)
        project_id = uuidutils.generate_uuid(dashed=False)

        with mock.patch('barbican.model.repositories.ProjectSecretStoreRepo.'
                        'get_secret_store_for_project') as pref_func:

            # set preferred secret store to one of value in config
            m_dict = {'store_plugin': 'ss_p3'}
            m_rec = mock.MagicMock()
            m_rec.secret_store.to_dict_fields.return_value = m_dict
            pref_func.return_value = m_rec

            objs = multiple_backends.get_applicable_store_plugins(
                ss_manager, project_id, None)
            self.assertIn(project_id, pref_func.call_args_list[0][0])
            self.assertIsInstance(objs, list)
            self.assertEqual(1, len(objs))
            self.assertIn('ss_p3', objs[0].get_plugin_name())

    def test_get_when_project_preferred_plugin_is_not_found_in_conf(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True)
        ss_manager = MockedManager(ss_plugins)

        project_id = uuidutils.generate_uuid(dashed=False)

        with mock.patch('barbican.model.repositories.ProjectSecretStoreRepo.'
                        'get_secret_store_for_project') as pref_func:

            # set preferred secret store value which is not defined in config
            m_dict = {'store_plugin': 'old_preferred_plugin'}
            m_rec = mock.MagicMock()
            m_rec.secret_store.to_dict_fields.return_value = m_dict
            pref_func.return_value = m_rec

            self.assertRaises(exception.MultipleStorePreferredPluginMissing,
                              multiple_backends.get_applicable_store_plugins,
                              ss_manager, project_id, None)
            self.assertIn(project_id, pref_func.call_args_list[0][0])

    def test_get_when_project_preferred_plugin_not_set_then_default_used(self):
        ss_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        # setting second plugin to be global default
        self.init_via_conf_file(ss_plugins, cr_plugins, enabled=True,
                                global_default_index=1)
        cr_manager = MockedManager(cr_plugins,
                                   plugin_lookup_field='crypto_plugin')
        project_id = uuidutils.generate_uuid(dashed=False)

        with mock.patch('barbican.plugin.util.multiple_backends.'
                        'get_global_default_secret_store') as gd_func:

            m_dict = {'crypto_plugin': 'cr_p2'}
            gd_func.return_value.to_dict_fields.return_value = m_dict
            objs = multiple_backends.get_applicable_crypto_plugins(cr_manager,
                                                                   project_id,
                                                                   None)
            gd_func.assert_called_once_with()
            self.assertIsInstance(objs, list)
            self.assertEqual(1, len(objs))
            self.assertIn('cr_p2', objs[0].get_plugin_name())

            # call again with no project_id set
            objs = multiple_backends.get_applicable_crypto_plugins(cr_manager,
                                                                   None, None)
            gd_func.assert_called_once_with()
            self.assertIsInstance(objs, list)
            self.assertEqual(1, len(objs))
            self.assertIn('cr_p2', objs[0].get_plugin_name())

    def test_get_applicable_store_plugins_when_multiple_backend_not_enabled(
            self):

        ss_config = config.get_module_config('secretstore')
        ss_plugins = ['ss_p11', 'ss_p22', 'ss_p33', 'ss_p44']
        ss_conf_plugins = ['ss_p1', 'ss_p2', 'ss_p3']
        cr_conf_plugins = ['cr_p1', 'cr_p2', 'cr_p3']
        self.init_via_conf_file(ss_conf_plugins, cr_conf_plugins,
                                enabled=False)
        ss_manager = MockedManager(ss_plugins)

        ss_config.set_override("enabled_secretstore_plugins",
                               ss_plugins, group='secretstore')

        objs = multiple_backends.get_applicable_store_plugins(ss_manager, None,
                                                              None)
        self.assertEqual(4, len(objs))


@test_utils.parameterized_test_case
class TestPluginsGenerateStoreAPIMultipleBackend(
        test_utils.MultipleBackendsTestCase):

    backend_dataset = {
        "db_backend": [{
            'store_plugins': ['store_crypto', 'kmip_plugin', 'store_crypto'],
            'crypto_plugins': ['simple_crypto', '', 'p11_crypto'],
            'default_store_class': store_crypto.StoreCryptoAdapterPlugin,
            'default_crypto_class': simple_crypto.SimpleCryptoPlugin
        }],
        "kmip": [{
            'store_plugins': ['kmip_plugin', 'store_crypto', 'store_crypto'],
            'crypto_plugins': ['', 'p11_crypto', 'simple_crypto'],
            'default_store_class': kss.KMIPSecretStore,
            'default_crypto_class': None
        }],
        "pkcs11": [{
            'store_plugins': ['store_crypto', 'store_crypto', 'kmip_plugin'],
            'crypto_plugins': ['p11_crypto', 'simple_crypto', ''],
            'default_store_class': store_crypto.StoreCryptoAdapterPlugin,
            'default_crypto_class': p11_crypto.P11CryptoPlugin
        }]
    }

    def setUp(self):
        super(TestPluginsGenerateStoreAPIMultipleBackend, self).setUp()

    def _create_project(self):
        session = repositories.get_project_repository().get_session()

        project = models.Project()
        project.external_id = ("keystone_project_id" +
                               uuidutils.generate_uuid(dashed=False))
        project.save(session=session)
        return project

    def _create_project_store(self, project_id, secret_store_id):
        proj_store_repo = repositories.get_project_secret_store_repository()
        session = proj_store_repo.get_session()

        proj_model = models.ProjectSecretStore(project_id, secret_store_id)

        proj_s_store = proj_store_repo.create_from(proj_model, session)
        proj_s_store.save(session=session)
        return proj_s_store

    @test_utils.parameterized_dataset(backend_dataset)
    def test_no_preferred_default_plugin(self, dataset):
        """Check name, plugin and crypto class used for default secret store

        Secret store name is crypto class plugin name if defined otherwise user
        friendly name is derived from store class plugin name
        """

        self.init_via_conf_file(dataset['store_plugins'],
                                dataset['crypto_plugins'],
                                enabled=True)

        with mock.patch('barbican.plugin.crypto.p11_crypto.P11CryptoPlugin.'
                        '_create_pkcs11'), \
                mock.patch('kmip.pie.client.ProxyKmipClient'):
            manager = secret_store.SecretStorePluginManager()

        keySpec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES, 128)

        plugin_found = manager.get_plugin_store(keySpec)
        self.assertIsInstance(plugin_found,
                              dataset['default_store_class'])

        global_secret_store = multiple_backends.\
            get_global_default_secret_store()

        if dataset['default_crypto_class']:
            crypto_plugin = cm.get_manager().get_plugin_store_generate(
                base.PluginSupportTypes.ENCRYPT_DECRYPT)
            self.assertIsInstance(crypto_plugin,
                                  dataset['default_crypto_class'])

            # make sure secret store name is same as crypto class friendly name
            # as store_plugin class is not direct impl of SecretStoreBase
            self.assertEqual(global_secret_store.name,
                             crypto_plugin.get_plugin_name())
        else:  # crypto class is not used
            # make sure secret store name is same as store plugin class
            # friendly name
            self.assertEqual(global_secret_store.name,
                             plugin_found.get_plugin_name())
            # error raised for no crypto plugin
            self.assertRaises(base.CryptoPluginNotFound,
                              cm.get_manager().get_plugin_store_generate,
                              base.PluginSupportTypes.ENCRYPT_DECRYPT)

    @test_utils.parameterized_dataset(backend_dataset)
    def test_project_preferred_default_plugin(self, dataset):
        """Check project preferred behavior with different global default"""

        self.init_via_conf_file(dataset['store_plugins'],
                                dataset['crypto_plugins'],
                                enabled=True)

        with mock.patch('barbican.plugin.crypto.p11_crypto.P11CryptoPlugin.'
                        '_create_pkcs11'), \
                mock.patch('kmip.pie.client.ProxyKmipClient'):
            manager = secret_store.SecretStorePluginManager()

        pkcs11_secret_store = self._get_secret_store_entry('store_crypto',
                                                           'p11_crypto')
        kmip_secret_store = self._get_secret_store_entry('kmip_plugin', None)
        db_secret_store = self._get_secret_store_entry('store_crypto',
                                                       'simple_crypto')

        project1 = self._create_project()
        project2 = self._create_project()
        project3 = self._create_project()

        # For project1 , make pkcs11 as preferred secret store
        self._create_project_store(project1.id, pkcs11_secret_store.id)
        # For project2 , make kmip as preferred secret store
        self._create_project_store(project2.id, kmip_secret_store.id)
        # For project3 , make db backend as preferred secret store
        self._create_project_store(project3.id, db_secret_store.id)

        keySpec = secret_store.KeySpec(secret_store.KeyAlgorithm.AES, 128)
        cm_manager = cm.get_manager()

        # For project1, verify store and crypto plugin instance used are pkcs11
        # specific
        plugin_found = manager.get_plugin_store(keySpec,
                                                project_id=project1.id)
        self.assertIsInstance(plugin_found,
                              store_crypto.StoreCryptoAdapterPlugin)
        crypto_plugin = cm.get_manager().get_plugin_store_generate(
            base.PluginSupportTypes.ENCRYPT_DECRYPT, project_id=project1.id)
        self.assertIsInstance(crypto_plugin, p11_crypto.P11CryptoPlugin)

        # For project2, verify store plugin instance is kmip specific
        # and there is no crypto plugin instance
        plugin_found = manager.get_plugin_store(keySpec,
                                                project_id=project2.id)
        self.assertIsInstance(plugin_found, kss.KMIPSecretStore)

        self.assertRaises(
            base.CryptoPluginNotFound, cm_manager.get_plugin_store_generate,
            base.PluginSupportTypes.ENCRYPT_DECRYPT, project_id=project2.id)

        # For project3, verify store and crypto plugin instance used are db
        # backend specific
        plugin_found = manager.get_plugin_store(keySpec,
                                                project_id=project3.id)
        self.assertIsInstance(plugin_found,
                              store_crypto.StoreCryptoAdapterPlugin)
        crypto_plugin = cm.get_manager().get_plugin_store_generate(
            base.PluginSupportTypes.ENCRYPT_DECRYPT, project_id=project3.id)
        self.assertIsInstance(crypto_plugin, simple_crypto.SimpleCryptoPlugin)

        # Make sure for project with no preferred setting, uses global default
        project4 = self._create_project()
        plugin_found = manager.get_plugin_store(keySpec,
                                                project_id=project4.id)
        self.assertIsInstance(plugin_found,
                              dataset['default_store_class'])
