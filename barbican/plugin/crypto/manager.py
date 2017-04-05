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
from barbican.plugin.crypto import base
from barbican.plugin.util import multiple_backends
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

config.set_module_config("crypto", CONF)


def list_opts():
    yield crypto_opt_group, crypto_opts


class _CryptoPluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_args=(), invoke_kwargs={}):
        """Crypto Plugin Manager

        Each time this class is initialized it will load a new instance
        of each enabled crypto plugin. This is undesirable, so rather than
        initializing a new instance of this class use the PLUGIN_MANAGER
        at the module level.
        """
        crypto_conf = config.get_module_config('crypto')
        plugin_names = self._get_internal_plugin_names(crypto_conf)

        super(_CryptoPluginManager, self).__init__(
            crypto_conf.crypto.namespace,
            plugin_names,
            invoke_on_load=False,  # Defer creating plugins to utility below.
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs,
            name_order=True  # extensions sorted as per order of plugin names
        )

        plugin_utils.instantiate_plugins(
            self, invoke_args, invoke_kwargs)

    def get_plugin_store_generate(self, type_needed, algorithm=None,
                                  bit_length=None, mode=None, project_id=None):
        """Gets a secret store or generate plugin that supports provided type.

        :param type_needed: PluginSupportTypes that contains details on the
        type of plugin required
        :returns: CryptoPluginBase plugin implementation
        """
        active_plugins = multiple_backends.get_applicable_crypto_plugins(
            self, project_id=project_id, existing_plugin_name=None)

        if not active_plugins:
            raise base.CryptoPluginNotFound()

        for generating_plugin in active_plugins:
            if generating_plugin.supports(
                    type_needed, algorithm, bit_length, mode):
                break
        else:
            operation = (u._("store or generate a secret of type {secret_type}"
                             " with algorithm {algorithm}, bit length "
                             "{bit_length}, and mode {mode}")
                         .format(secret_type=type_needed,
                                 algorithm=algorithm,
                                 bit_length=bit_length,
                                 mode=mode))
            raise base.CryptoPluginUnsupportedOperation(operation=operation)

        return generating_plugin

    def get_plugin_retrieve(self, plugin_name_for_store):
        """Gets a secret retrieve plugin that supports the provided type.

        :param type_needed: PluginSupportTypes that contains details on the
        type of plugin required
        :returns: CryptoPluginBase plugin implementation
        """
        active_plugins = plugin_utils.get_active_plugins(self)

        if not active_plugins:
            raise base.CryptoPluginNotFound()

        for decrypting_plugin in active_plugins:
            plugin_name = utils.generate_fullname_for(decrypting_plugin)
            if plugin_name == plugin_name_for_store:
                break
        else:
            operation = (u._("retrieve a secret from plugin: {plugin}")
                         .format(plugin=plugin_name_for_store))
            raise base.CryptoPluginUnsupportedOperation(operation=operation)

        return decrypting_plugin

    def _get_internal_plugin_names(self, crypto_conf):
        """Gets plugin names used for loading via stevedore.

        When multiple secret store support is enabled, then crypto plugin names
        are read via updated configuration structure. If not enabled, then it
        reads MultiStr property in 'crypto' config section.
        """
        # to cache default global secret store value on first use
        self.global_default_store_dict = None
        if utils.is_multiple_backends_enabled():
            parsed_stores = multiple_backends.read_multiple_backends_config()
            plugin_names = [store.crypto_plugin for store in parsed_stores
                            if store.crypto_plugin]
        else:
            plugin_names = crypto_conf.crypto.enabled_crypto_plugins
        return plugin_names


def get_manager():
    """Return a singleton crypto plugin manager."""
    global _PLUGIN_MANAGER
    global _PLUGIN_MANAGER_LOCK
    if not _PLUGIN_MANAGER:
        with _PLUGIN_MANAGER_LOCK:
            if not _PLUGIN_MANAGER:
                _PLUGIN_MANAGER = _CryptoPluginManager()
    return _PLUGIN_MANAGER
