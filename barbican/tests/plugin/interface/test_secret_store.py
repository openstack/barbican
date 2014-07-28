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
import testtools

from barbican.plugin.interface import secret_store as str


class TestSecretStore(str.SecretStoreBase):
    """Secret store plugin for testing support."""

    def __init__(self, generate_supports_response):
        super(TestSecretStore, self).__init__()
        self.generate_supports_response = generate_supports_response

    def generate_symmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def generate_asymmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def store_secret(self, secret_dto):
        raise NotImplementedError  # pragma: no cover

    def get_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def generate_supports(self, key_spec):
        return self.generate_supports_response

    def delete_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover


class TestSecretStoreWithTransportKey(str.SecretStoreBase):
    """Secret store plugin for testing support.

    This plugin will override the relevant methods for key wrapping.
    """

    def __init__(self, generate_supports_response):
        super(TestSecretStoreWithTransportKey, self).__init__()
        self.generate_supports_response = generate_supports_response

    def generate_symmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def generate_asymmetric_key(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    def store_secret(self, secret_dto):
        raise NotImplementedError  # pragma: no cover

    def get_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def generate_supports(self, key_spec):
        return self.generate_supports_response

    def delete_secret(self, secret_metadata):
        raise NotImplementedError  # pragma: no cover

    def get_transport_key(self):
        return "transport key"

    def is_transport_key_current(self, transport_key):
        return True


class WhenTestingSecretStorePluginManager(testtools.TestCase):

    def setUp(self):
        super(WhenTestingSecretStorePluginManager, self).setUp()
        self.manager = str.SecretStorePluginManager()

    def test_get_store_supported_plugin(self):
        plugin = TestSecretStore(True)
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]

        self.assertEqual(plugin,
                         self.manager.get_plugin_store())

    def test_get_generate_supported_plugin(self):
        plugin = TestSecretStore(True)
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec('AES', 128)

        self.assertEqual(plugin,
                         self.manager.get_plugin_generate(keySpec))

    def test_get_store_no_plugin_found(self):
        self.manager.extensions = []
        self.assertRaises(
            str.SecretStorePluginNotFound,
            self.manager.get_plugin_store,
        )

    def test_get_generate_no_plugin_found(self):
        self.manager.extensions = []
        keySpec = str.KeySpec('AES', 128)
        self.assertRaises(
            str.SecretStorePluginNotFound,
            self.manager.get_plugin_generate,
            keySpec,
        )

    def test_get_generate_no_supported_plugin(self):
        plugin = TestSecretStore(False)
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        keySpec = str.KeySpec('AES', 128)
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_generate,
            keySpec,
        )

    def test_get_store_no_plugin_with_tkey(self):
        plugin = TestSecretStore(False)
        plugin_mock = mock.MagicMock(obj=plugin)
        self.manager.extensions = [plugin_mock]
        self.assertRaises(
            str.SecretStoreSupportedPluginNotFound,
            self.manager.get_plugin_store,
            transport_key_needed=True,
        )

    def test_get_store_with_tkey(self):
        plugin1 = TestSecretStore(False)
        plugin1_mock = mock.MagicMock(obj=plugin1)
        plugin2 = TestSecretStoreWithTransportKey(False)
        plugin2_mock = mock.MagicMock(obj=plugin2)
        self.manager.extensions = [plugin1_mock, plugin2_mock]
        self.assertEqual(
            plugin2,
            self.manager.get_plugin_store(transport_key_needed=True))
