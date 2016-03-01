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

from oslo_config import cfg
from stevedore import named
import threading

from barbican.common import config
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin.crypto import crypto
from barbican.plugin.interface import secret_store
from barbican.plugin.util import utils as plugin_utils


_PLUGIN_MANAGER = None
_PLUGIN_MANAGER_LOCK = threading.RLock()

CONF = config.new_config()

DEFAULT_PLUGIN_NAMESPACE = 'barbican.crypto.plugin'
DEFAULT_PLUGINS = ['simple_crypto']

crypto_opt_group = cfg.OptGroup(name='crypto',
                                title='Crypto Plugin Options')
crypto_opts = [
    cfg.StrOpt('namespace',
               default=DEFAULT_PLUGIN_NAMESPACE,
               help=u._('Extension namespace to search for plugins.')
               ),
    cfg.MultiStrOpt('enabled_crypto_plugins',
                    default=DEFAULT_PLUGINS,
                    help=u._('List of crypto plugins to load.')
                    )
]
CONF.register_group(crypto_opt_group)
CONF.register_opts(crypto_opts, group=crypto_opt_group)
config.parse_args(CONF)


class _CryptoPluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_args=(), invoke_kwargs={}):
        """Crypto Plugin Manager

        Each time this class is initialized it will load a new instance
        of each enabled crypto plugin. This is undesirable, so rather than
        initializing a new instance of this class use the PLUGIN_MANAGER
        at the module level.
        """
        super(_CryptoPluginManager, self).__init__(
            conf.crypto.namespace,
            conf.crypto.enabled_crypto_plugins,
            invoke_on_load=False,  # Defer creating plugins to utility below.
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

        plugin_utils.instantiate_plugins(
            self, invoke_args, invoke_kwargs)

    def get_plugin_store_generate(self, type_needed, algorithm=None,
                                  bit_length=None, mode=None):
        """Gets a secret store or generate plugin that supports provided type.

        :param type_needed: PluginSupportTypes that contains details on the
        type of plugin required
        :returns: CryptoPluginBase plugin implementation
        """
        active_plugins = plugin_utils.get_active_plugins(self)

        if not active_plugins:
            raise crypto.CryptoPluginNotFound()

        for generating_plugin in active_plugins:
            if generating_plugin.supports(
                    type_needed, algorithm, bit_length, mode):
                break
        else:
            raise secret_store.SecretStorePluginNotFound()

        return generating_plugin

    def get_plugin_retrieve(self, plugin_name_for_store):
        """Gets a secret retrieve plugin that supports the provided type.

        :param type_needed: PluginSupportTypes that contains details on the
        type of plugin required
        :returns: CryptoPluginBase plugin implementation
        """
        active_plugins = plugin_utils.get_active_plugins(self)

        if not active_plugins:
            raise crypto.CryptoPluginNotFound()

        for decrypting_plugin in active_plugins:
            plugin_name = utils.generate_fullname_for(decrypting_plugin)
            if plugin_name == plugin_name_for_store:
                break
        else:
            raise secret_store.SecretStorePluginNotFound()

        return decrypting_plugin


def get_manager():
    """Return a singleton crypto plugin manager."""
    global _PLUGIN_MANAGER
    global _PLUGIN_MANAGER_LOCK
    if not _PLUGIN_MANAGER:
        with _PLUGIN_MANAGER_LOCK:
            if not _PLUGIN_MANAGER:
                _PLUGIN_MANAGER = _CryptoPluginManager()
    return _PLUGIN_MANAGER
