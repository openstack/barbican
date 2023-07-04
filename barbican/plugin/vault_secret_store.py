# Copyright (c) 2018 Red Hat Inc.
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

from barbican.common import config
import barbican.plugin.castellan_secret_store as css
from castellan.i18n import _
from castellan import options
from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger(__name__)

DEFAULT_VAULT_URL = "http://127.0.0.1:8200"
DEFAULT_MOUNTPOINT = "secret"

vault_opt_group = cfg.OptGroup(name='vault_plugin', title='Vault Plugin')
vault_opts = [
    cfg.StrOpt('root_token_id',
               help='root token for vault'),
    cfg.StrOpt('approle_role_id',
               help='AppRole role_id for authentication with vault'),
    cfg.StrOpt('approle_secret_id',
               help='AppRole secret_id for authentication with vault'),
    cfg.StrOpt('kv_mountpoint',
               default=DEFAULT_MOUNTPOINT,
               help='Mountpoint of KV store in Vault to use, for example: '
                    '{}'.format(DEFAULT_MOUNTPOINT)),
    cfg.StrOpt('vault_url',
               default=DEFAULT_VAULT_URL,
               help='Use this endpoint to connect to Vault, for example: '
                    '"%s"' % DEFAULT_VAULT_URL),
    cfg.StrOpt('ssl_ca_crt_file',
               help='Absolute path to ca cert file'),
    cfg.BoolOpt('use_ssl',
                default=False,
                help=_('SSL Enabled/Disabled')),
    cfg.StrOpt("namespace",
               help=_("Vault Namespace to use for all requests. "
                      "Namespaces is a feature available in HasiCorp Vault "
                      "Enterprise only.")),
]

CONF = config.new_config()
CONF.register_group(vault_opt_group)
CONF.register_opts(vault_opts, group=vault_opt_group)
config.parse_args(CONF)


def list_opts():
    yield vault_opt_group, vault_opts    # pragma: no cover


class VaultSecretStore(css.CastellanSecretStore):

    def __init__(self, conf=CONF):
        """Constructor - create the vault secret store."""
        vault_conf = self.get_conf(conf)
        self._set_params(vault_conf)

    def get_plugin_name(self):
        return "VaultSecretStore"

    def get_conf(self, conf=CONF):
        """Convert secret store conf into oslo conf

        Returns an oslo.config() object to pass to keymanager.API(conf)
        """
        vault_conf = cfg.ConfigOpts()
        options.set_defaults(
            vault_conf,
            backend='vault',
            vault_root_token_id=conf.vault_plugin.root_token_id,
            vault_approle_role_id=conf.vault_plugin.approle_role_id,
            vault_approle_secret_id=conf.vault_plugin.approle_secret_id,
            vault_kv_mountpoint=conf.vault_plugin.kv_mountpoint,
            vault_url=conf.vault_plugin.vault_url,
            vault_ssl_ca_crt_file=conf.vault_plugin.ssl_ca_crt_file,
            vault_use_ssl=conf.vault_plugin.use_ssl,
            vault_namespace=conf.vault_plugin.namespace
        )
        return vault_conf

    def store_secret_supports(self, key_spec):
        return True

    def generate_supports(self, key_spec):
        return True
