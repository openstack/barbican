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

from oslo_config import cfg

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u

LOG = utils.getLogger(__name__)

LOOKUP_PLUGINS_PREFIX = "secretstore:"


def read_multiple_backends_config():
    """Reads and validates multiple backend related configuration.

    Multiple backends configuration is read only when multiple secret store
    flag is enabled.
    Configuration is validated to make sure that section specific to
    provided suffix exists in service configuration. Also validated that only
    one of section has global_default = True and its not missing.
    """
    conf = config.get_module_config('secretstore')

    parsed_stores = None
    if utils.is_multiple_backends_enabled():
        suffix_list = conf.secretstore.stores_lookup_suffix
        if not suffix_list:
            raise exception.MultipleSecretStoreLookupFailed()

        def register_options_dynamically(conf, group_name):
            store_opt_group = cfg.OptGroup(
                name=group_name, title='Plugins needed for this backend')
            store_opts = [
                cfg.StrOpt('secret_store_plugin',
                           default=None,
                           help=u._('Internal name used to identify'
                                    'secretstore_plugin')
                           ),
                cfg.StrOpt('crypto_plugin',
                           default=None,
                           help=u._('Internal name used to identify '
                                    'crypto_plugin.')
                           ),
                cfg.BoolOpt('global_default',
                            default=False,
                            help=u._('Flag to indicate if this plugin is '
                                     'global default plugin for deployment. '
                                     'Default is False.')
                            ),
                ]
            conf.register_group(store_opt_group)
            conf.register_opts(store_opts, group=store_opt_group)

        group_names = []
        # construct group names using those suffix and dynamically register
        # oslo config options under that group name
        for suffix in suffix_list:
            group_name = LOOKUP_PLUGINS_PREFIX + suffix
            register_options_dynamically(conf, group_name)
            group_names.append(group_name)

        store_conf = collections.namedtuple('store_conf', ['store_plugin',
                                                           'crypto_plugin',
                                                           'global_default'])
        parsed_stores = []
        global_default_count = 0
        # Section related to group names based of suffix list are always found
        # as we are dynamically registering group and its options.
        for group_name in group_names:
            conf_section = getattr(conf, group_name)
            if conf_section.global_default:
                global_default_count += 1

            store_plugin = conf_section.secret_store_plugin
            if not store_plugin:
                raise exception.MultipleStorePluginValueMissing(conf_section)

            parsed_stores.append(store_conf(store_plugin,
                                            conf_section.crypto_plugin,
                                            conf_section.global_default))

        if global_default_count != 1:
            raise exception.MultipleStoreIncorrectGlobalDefault(
                global_default_count)

    return parsed_stores
