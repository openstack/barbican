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
from barbican.model import models as db_models
from barbican.model import repositories as db_repos

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
                           help=u._('Internal name used to identify'
                                    'secretstore_plugin')
                           ),
                cfg.StrOpt('crypto_plugin',
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


def sync_secret_stores(secretstore_manager, crypto_manager=None):
    """Synchronize secret store plugin names between service conf and database

    This method reads secret and crypto store plugin name from service
    configuration and then synchronizes corresponding data maintained in
    database SecretStores table.

    Any new plugin name(s) added in service configuration is added as a new
    entry in SecretStores table. If global_default value is changed for
    existing plugins, then global_default flag is updated to reflect that
    change in database. If plugin name is removed from service configuration,
    then removal is possible as long as respective plugin names are NOT set as
    preferred secret store for a project. If it is used and plugin name is
    removed, then error is raised. This logic is intended to be invoked at
    server startup so any error raised here will result in critical failure.
    """
    if not utils.is_multiple_backends_enabled():
        return

    # doing local import to avoid circular dependency between manager and
    # current utils module
    from barbican.plugin.crypto import manager as cm

    secret_stores_repo = db_repos.get_secret_stores_repository()
    proj_store_repo = db_repos.get_project_secret_store_repository()
    if crypto_manager is None:
        crypto_manager = cm.get_manager()

    def get_friendly_name_dict(ext_manager):
        """Returns dict of plugin internal name and friendly name entries."""
        names_dict = {}
        for ext in ext_manager.extensions:
            if ext.obj and hasattr(ext.obj, 'get_plugin_name'):
                names_dict[ext.name] = ext.obj.get_plugin_name()
        return names_dict

    ss_friendly_names = get_friendly_name_dict(secretstore_manager)
    crypto_friendly_names = get_friendly_name_dict(crypto_manager)
    # get existing secret stores data from database
    db_stores = secret_stores_repo.get_all()

    # read secret store data from service configuration
    conf_stores = []
    for parsed_store in secretstore_manager.parsed_stores:
        crypto_plugin = parsed_store.crypto_plugin
        if not crypto_plugin:
            crypto_plugin = None

        if crypto_plugin:
            friendly_name = crypto_friendly_names.get(crypto_plugin)
        else:
            friendly_name = ss_friendly_names.get(parsed_store.store_plugin)

        conf_stores.append(db_models.SecretStores(
            name=friendly_name, store_plugin=parsed_store.store_plugin,
            crypto_plugin=crypto_plugin,
            global_default=parsed_store.global_default))

    if db_stores:
        def fn_match(lh_store, rh_store):
            return (lh_store.store_plugin == rh_store.store_plugin and
                    lh_store.crypto_plugin == rh_store.crypto_plugin)

        for conf_store in conf_stores:
            # find existing db entry for plugin using conf based plugin names
            db_store_match = next((db_store for db_store in db_stores if
                                   fn_match(conf_store, db_store)), None)
            if db_store_match:
                # update existing db entry if global default is changed now
                if db_store_match.global_default != conf_store.global_default:
                    db_store_match.global_default = conf_store.global_default
                    # persist flag change.
                    db_store_match.save()
                # remove matches store from local list after processing
                db_stores.remove(db_store_match)
            else:  # new conf entry as no match found in existing entries
                secret_stores_repo.create_from(conf_store)

        # entries still present in db list are no longer configured in service
        # configuration, so try to remove them provided there is no project
        # is using it as preferred secret store.
        for db_store in db_stores:
            if proj_store_repo.get_count_by_secret_store(db_store.id) == 0:
                secret_stores_repo.delete_entity_by_id(db_store.id, None)
            else:
                raise exception.MultipleStorePluginStillInUse(db_store.name)
    else:  # initial setup case when there is no secret stores data in db
        for conf_store in conf_stores:
            secret_stores_repo.create_from(conf_store)


def get_global_default_secret_store():
    secret_store_repo = db_repos.get_secret_stores_repository()

    default_ss = None
    for secret_store in secret_store_repo.get_all():
        if secret_store.global_default:
            default_ss = secret_store
            break
    return default_ss


def get_applicable_crypto_plugins(manager, project_id, existing_plugin_name):
    """Get list of crypto plugins available for use.

    :param: manager instance of crypto manager
    :param: project_id project to identify preferred store if set
    :param: existing_plugin_name full plugin name. If a secret has an existing
            plugin defined, then we do not care if any preferred plugins have
            been defined. We will return all configured plugins as if multiple
            plugin support was not enabled. Subsequent code in the caller will
            select the plugin by name.

    When multiple backends support is enabled:
    It return project preferred plugin as list when it is setup earlier.
    If project preferred plugin is not set, then it uses plugin from default
    secret store.
    Plugin name is 'crypto_plugin' field value on identified secret store data.
    It returns matched plugin as list to match existing functionality.

    When multiple backends support is NOT enabled:
    In this case, it just returns list of all active plugins which is
    existing functionality before support for multiple backends is added.
    """
    return _get_applicable_plugins_for_type(manager, project_id,
                                            existing_plugin_name,
                                            'crypto_plugin')


def get_applicable_store_plugins(manager, project_id, existing_plugin_name):
    """Get list of secret store plugins available for use.

    :param: manager instance of secret store manager
    :param: project_id project to identify preferred store if set
    :param: existing_plugin_name full plugin name. If a secret has an existing
            plugin defined, then we do not care if any preferred plugins have
            been defined. We will return all configured plugins as if multiple
            plugin support was not enabled. Subsequent code in the caller will
            select the plugin by name.

    When multiple backends support is enabled:
    It return project preferred plugin as list when it is setup earlier.
    If project preferred plugin is not set, then it uses plugin from default
    secret store.
    Plugin name is 'store_plugin' field value on identified secret store data.
    It returns matched plugin as list to match existing functionality.

    When multiple backends support is NOT enabled:
    In this case, it just returns list of all active plugins which is
    existing functionality before support for multiple backends is added.
    """
    return _get_applicable_plugins_for_type(manager, project_id,
                                            existing_plugin_name,
                                            'store_plugin')


def _get_applicable_plugins_for_type(manager, project_id, existing_plugin_name,
                                     plugin_type_field):

    plugins = []
    plugin_dict = {ext.name: ext.obj for ext in manager.extensions if ext.obj}
    if utils.is_multiple_backends_enabled() and existing_plugin_name is None:
        proj_store_repo = db_repos.get_project_secret_store_repository()
        plugin_store = proj_store_repo.get_secret_store_for_project(
            project_id, None, suppress_exception=True)

        # If project specific store is not set, then use global default one.
        if not plugin_store:
            if manager.global_default_store_dict is None:
                # Need to cache data as dict instead of db object to be usable
                # across various request sqlalchemy sessions
                store_dict = get_global_default_secret_store().to_dict_fields()
                manager.global_default_store_dict = store_dict
            secret_store_data = manager.global_default_store_dict
        else:
            secret_store_data = plugin_store.secret_store.to_dict_fields()

        applicable_plugin_name = secret_store_data[plugin_type_field]
        if applicable_plugin_name in plugin_dict:
            plugins = [plugin_dict.get(applicable_plugin_name)]
        elif applicable_plugin_name:  # applicable_plugin_name has value
            raise exception.MultipleStorePreferredPluginMissing(
                applicable_plugin_name)
    else:
        plugins = plugin_dict.values()

    return plugins
