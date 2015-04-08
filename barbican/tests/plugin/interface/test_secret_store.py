# Copyright (c) 2014 Johns Hopkins University Applied Physics Laboratory
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

import mock

from barbican.common import utils as common_utils
from barbican.plugin.interface import secret_store as str
from barbican.tests import utils


class TestSecretStore(str.SecretStoreBase):
    """Secret store plugin for testing support."""

    def __init__(self, supported_alg_list):
        super(TestSecretStore, self).__init__()
        self.alg_list = supported_alg_list

    def generate_symmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def generate_asymmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def store_secret(self, secret_dto):
        raise NotImplementedError  # pragma: no cover

    def get_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def generate_supports(self, key_spec):
        return key_spec.alg in self.alg_list

    def delete_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def store_secret_supports(self, key_spec):
        return key_spec.alg in self.alg_list


class TestSecretStoreWithTransportKey(str.SecretStoreBase):
    """Secret store plugin for testing support.

    This plugin will override the relevant methods for key wrapping.
    """

    def __init__(self, supported_alg_list):
        super(TestSecretStoreWithTransportKey, self).__init__()
        self.alg_list = supported_alg_list

    def generate_symmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def generate_asymmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def store_secret(self, secret_dto):
        raise NotImplementedError  # pragma: no cover

    def get_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def generate_supports(self, key_spec):
        return key_spec.alg in self.alg_list

    def delete_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def store_secret_supports(self, key_spec):
        return key_spec.alg in self.alg_list

    def get_transport_key(self):
        return "transport key"

    def is_transport_key_current(self, transport_key):
        return True


class WhenTestingSecretStorePluginManager(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretStorePluginManager, self).setUp()
        self.manager = str.SecretStorePluginManager()

    def test_get_store_supported_plugin_no_plugin_name(self):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)

        self.assertEqual(plugin,
                         self.manager.get_plugin_store(keySpec))

    def test_get_store_supported_plugin_with_plugin_name(self):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]

        plugin_found = self.manager.get_plugin_store(
            None, plugin_name=common_utils.generate_fullname_for(plugin))
        self.assertEqual(plugin, plugin_found)

    def test_get_generate_supported_plugin(self):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)

        self.assertEqual(plugin,
                         self.manager.get_plugin_generate(keySpec))

    def test_get_store_no_plugin_found(self):
        self.manager.extensions = []
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStorePluginsNotConfigured,
            self.manager.get_plugin_store,
            keySpec,
        )

    def test_get_store_no_plugin_found_by_name(self):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]

        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        plugin_name = 'plugin'

        exception_result = self.assertRaises(
            str.SecretStorePluginNotFound,
            self.manager.get_plugin_store,
            keySpec,
            plugin_name=plugin_name
        )

        self.assertEqual(
            'Secret store plugin "{name}" not found.'.format(name=plugin_name),
            exception_result.message)

    def test_get_generate_no_plugin_found(self):
        self.manager.extensions = []
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStorePluginsNotConfigured,
            self.manager.get_plugin_generate,
            keySpec,
        )

    def test_get_store_no_supported_plugin(self):
        plugin = TestSecretStore([])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_store,
            keySpec,
        )

    def test_get_generate_no_supported_plugin(self):
        plugin = TestSecretStore([])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_generate,
            keySpec,
        )

    def test_get_store_no_plugin_with_tkey_and_no_supports_storage(self):
        plugin = TestSecretStore([])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_store,
            key_spec=keySpec,
            transport_key_needed=True,
        )

    def test_get_store_plugin_with_tkey_and_no_supports_storage(self):
        plugin = TestSecretStoreWithTransportKey([])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_store,
            key_spec=keySpec,
            transport_key_needed=True,
        )

    def test_get_store_plugin_with_no_tkey_and_supports_storage(self):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_store,
            key_spec=keySpec,
            transport_key_needed=True,
        )

    @mock.patch('barbican.common.utils.generate_fullname_for')
    def test_get_retrieve_plugin_raises_when_not_available(
            self, generate_full_name_for):
        plugin = TestSecretStore([str.KeyAlgorithm.AES])
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]

        generate_full_name_for.return_value = "another plugin name"
        plugin_name = 'plugin name searched for'

        exception_result = self.assertRaises(
            str.StorePluginNotAvailableOrMisconfigured,
            self.manager.get_plugin_retrieve_delete,
            plugin_name=plugin_name,
        )
        self.assertIn(plugin_name, exception_result.message)

    def test_get_store_plugin_with_tkey_and_supports_storage(self):
        plugin1 = TestSecretStore([str.KeyAlgorithm.AES])
        plugin1_mock = mock.MagicMock(obj=plugin1)
        plugin2 = TestSecretStoreWithTransportKey([str.KeyAlgorithm.AES])
        plugin2_mock = mock.MagicMock(obj=plugin2)
        self.manager.extensions = [plugin1_mock, plugin2_mock]
        keySpec = str.KeySpec(str.KeyAlgorithm.AES, 128)
        self.assertEqual(plugin2,
                         self.manager.get_plugin_store(
                             key_spec=keySpec,
                             transport_key_needed=True))
