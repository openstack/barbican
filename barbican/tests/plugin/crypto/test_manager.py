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

import mock
import threading

from barbican.common import utils as common_utils
from barbican.plugin.crypto import crypto
from barbican.plugin.crypto import manager as cm
from barbican.plugin.interface import secret_store
from barbican.tests import utils


class MyThread(threading.Thread):
    def __init__(self, index, results):
        threading.Thread.__init__(self)
        self.index = index
        self.results = results

    def run(self):
        self.results[self.index] = cm.get_manager()


class WhenTestingManager(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingManager, self).setUp()

        self.plugin_returned = mock.MagicMock()
        self.plugin_type = crypto.PluginSupportTypes.ENCRYPT_DECRYPT
        self.plugin_returned.supports.return_value = True
        self.plugin_name = common_utils.generate_fullname_for(
            self.plugin_returned)
        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)
        self.manager = cm.get_manager()
        self.manager.extensions = [self.plugin_loaded]

    def test_can_override_enabled_plugins(self):
        """Verify can override default configuration for plugin selection."""
        # Reset manager singleton otherwise we have test execution
        # order problems
        cm._PLUGIN_MANAGER = None

        cm.CONF.set_override(
            "enabled_crypto_plugins",
            ['foo_plugin'],
            group='crypto',
            enforce_type=True)

        manager_to_test = cm.get_manager()

        self.assertIsInstance(
            manager_to_test, cm._CryptoPluginManager)

        self.assertListEqual(['foo_plugin'],
                             manager_to_test._names)

    def test_get_plugin_store_generate(self):
        self.assertEqual(
            self.plugin_returned,
            self.manager.get_plugin_store_generate(self.plugin_type))

    def test_raises_error_with_wrong_plugin_type(self):
        self.plugin_returned.supports.return_value = False
        self.assertRaises(
            secret_store.SecretStorePluginNotFound,
            self.manager.get_plugin_store_generate,
            self.plugin_type)

    def test_raises_error_with_no_active_store_generate_plugin(self):
        self.manager.extensions = []
        self.assertRaises(
            crypto.CryptoPluginNotFound,
            self.manager.get_plugin_store_generate,
            self.plugin_type)

    def test_get_plugin_retrieve(self):
        self.assertEqual(
            self.plugin_returned,
            self.manager.get_plugin_retrieve(self.plugin_name))

    def test_raises_error_with_wrong_plugin_name(self):
        self.assertRaises(
            secret_store.SecretStorePluginNotFound,
            self.manager.get_plugin_retrieve,
            'other-name')

    def test_raises_error_with_no_active_plugin_name(self):
        self.manager.extensions = []
        self.assertRaises(
            crypto.CryptoPluginNotFound,
            self.manager.get_plugin_retrieve,
            self.plugin_name)

    def test_get_manager_with_multi_threads(self):
        self.manager.extensions = []
        self.manager = None
        results = [None] * 10
        # setup 10 threads to call get_manager() at same time
        for i in range(10):
            t = MyThread(i, results)
            t.start()
        # verify all threads return one and same plugin manager
        for i in range(10):
            self.assertIsInstance(results[i], cm._CryptoPluginManager)
            self.assertEqual(results[0], results[i])
