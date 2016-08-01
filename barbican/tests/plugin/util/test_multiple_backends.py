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
import mock

from barbican.common import config
from barbican.common import exception
from barbican.plugin.util import multiple_backends
from barbican.tests import utils as test_utils


class MockedManager(object):

    NAME_PREFIX = "friendly_"

    def __init__(self, names):
        ExtTuple = collections.namedtuple('ExtTuple', ['name', 'obj'])
        self.extensions = []
        for name in names:
            m = mock.MagicMock()
            m.get_plugin_name.return_value = self.NAME_PREFIX + name
            new_extension = ExtTuple(name, m)
            self.extensions.append(new_extension)


class WhenReadingMultipleBackendsConfig(test_utils.MultipleBackendsTestCase):

    def setUp(self):
        super(WhenReadingMultipleBackendsConfig, self).setUp()

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
        self.assertEqual(True, stores[1].global_default)
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
        conf.set_override("stores_lookup_suffix", [], group='secretstore',
                          enforce_type=True)
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
