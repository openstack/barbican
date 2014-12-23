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

from barbican.plugin.crypto import manager
from barbican.tests import utils


class WhenTestingManager(utils.BaseTestCase):

    def test_can_override_enabled_plugins(self):
        """Verify can override default configuration for plugin selection."""
        manager.CONF.set_override(
            "enabled_crypto_plugins",
            ['foo_plugin'],
            group='crypto')

        manager_to_test = manager.get_manager()

        self.assertIsInstance(
            manager_to_test, manager._CryptoPluginManager)

        self.assertListEqual(['foo_plugin'],
                             manager_to_test._names)
