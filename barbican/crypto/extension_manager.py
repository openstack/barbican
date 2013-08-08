# Copyright (c) 2013 Rackspace, Inc.
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

from oslo.config import cfg
from stevedore import named

from barbican.common.exception import BarbicanException
from barbican.common import utils
from barbican.crypto import mime_types
from barbican.crypto import plugin as plugin_mod
from barbican.model.models import EncryptedDatum
from barbican.openstack.common.gettextutils import _


CONF = cfg.CONF
DEFAULT_PLUGIN_NAMESPACE = 'barbican.crypto.plugin'
DEFAULT_PLUGINS = ['simple_crypto']

crypto_opt_group = cfg.OptGroup(name='crypto',
                                title='Crypto Plugin Options')
crypto_opts = [
    cfg.StrOpt('namespace',
               default=DEFAULT_PLUGIN_NAMESPACE,
               help=_('Extension namespace to search for plugins.')
               ),
    cfg.MultiStrOpt('enabled_crypto_plugins',
                    default=DEFAULT_PLUGINS,
                    help=_('List of crypto plugins to load.')
                    )
]
CONF.register_group(crypto_opt_group)
CONF.register_opts(crypto_opts, group=crypto_opt_group)


class CryptoMimeTypeNotSupportedException(BarbicanException):
    """Raised when support for requested mime type is
    not available in any active plugin."""
    def __init__(self, mime_type):
        super(CryptoMimeTypeNotSupportedException, self).__init__(
            _("Crypto Mime Type of '{0}' not supported").format(mime_type)
        )
        self.mime_type = mime_type


class CryptoAcceptNotSupportedException(BarbicanException):
    """Raised when requested decrypted format is not
    available in any active plugin."""
    def __init__(self, accept):
        super(CryptoAcceptNotSupportedException, self).__init__(
            _("Crypto Accept of '{0}' not supported").format(accept)
        )
        self.accept = accept


class CryptoNoSecretOrDataException(BarbicanException):
    """Raised when secret information is not available for the specified
    secret mime-type."""
    def __init__(self, secret_id):
        super(CryptoNoSecretOrDataException, self).__init__(
            _('No secret information available for '
              'secret {0}').format(secret_id)
        )
        self.secret_id = secret_id


class CryptoPluginNotFound(BarbicanException):
    """Raised when no plugins are installed."""
    message = "Crypto plugin not found."


class CryptoExtensionManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_on_load=True,
                 invoke_args=(), invoke_kwargs={}):
        super(CryptoExtensionManager, self).__init__(
            conf.crypto.namespace,
            conf.crypto.enabled_crypto_plugins,
            invoke_on_load=invoke_on_load,
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

    def encrypt(self, unencrypted, content_type, secret, tenant, kek_repo):
        """Delegates encryption to first active plugin."""
        if len(self.extensions) < 1:
            raise CryptoPluginNotFound()
        encrypting_plugin = self.extensions[0].obj
        # TODO: Need to test if the plugin supports 'secret's requirements.

        if content_type in mime_types.PLAIN_TEXT:
            # normalize text to binary string
            unencrypted = unencrypted.encode('utf-8')

        # Find or create a key encryption key metadata.
        kek_datum, kek_metadata = self._find_or_create_kek_metadata(
            encrypting_plugin, tenant, kek_repo)

        # Create an encrypted datum instance and add the encrypted cypher text.
        datum = EncryptedDatum(secret, kek_datum)
        datum.content_type = content_type
        datum.cypher_text, datum.kek_meta_extended = encrypting_plugin.encrypt(
            unencrypted, kek_metadata, tenant
        )
        return datum

    def decrypt(self, accept, secret, tenant):
        """Delegates decryption to active plugins."""

        if not secret or not secret.encrypted_data:
            raise CryptoNoSecretOrDataException(secret.id)

        if not mime_types.is_supported(accept):
            raise CryptoAcceptNotSupportedException(accept)

        for ext in self.extensions:
            decrypting_plugin = ext.obj
            for datum in secret.encrypted_data:
                if self._plugin_supports(decrypting_plugin,
                                         datum.kek_meta_tenant):
                    unencrypted = decrypting_plugin \
                        .decrypt(datum.cypher_text,
                                 datum.kek_meta_tenant,
                                 datum.kek_meta_extended,
                                 tenant)
                    if datum.content_type in mime_types.PLAIN_TEXT:
                        unencrypted = unencrypted.decode('utf-8')
                    return unencrypted
        else:
            raise CryptoPluginNotFound()

    def generate_data_encryption_key(self, secret, content_type, tenant,
                                     kek_repo):
        """
        Delegates generating a data-encryption key to first active plugin.

        Note that this key can be used by clients for their encryption
        processes. This generated key is then be encrypted via
        the plug-in key encryption process, and that encrypted datum
        is then returned from this method.
        """
        if len(self.extensions) < 1:
            raise CryptoPluginNotFound()
        encrypting_plugin = self.extensions[0].obj

        # Create the secret.
        data_key = encrypting_plugin.create(secret.algorithm,
                                            secret.bit_length)

        # Encrypt the secret.
        return self.encrypt(data_key, content_type, secret, tenant, kek_repo)

    def _plugin_supports(self, plugin_inst, kek_metadata_tenant):
        """
        Tests if the supplied plugin supports operations on the supplied
        key encryption key (KEK) metadata.

        :param plugin_inst: The plugin instance to test.
        :param kek_metadata: The KEK metadata to test.
        :return: True if the plugin can support operations on the KEK metadata.

        """
        plugin_name = utils.generate_fullname_for(plugin_inst)
        return plugin_name == kek_metadata_tenant.plugin_name

    def _find_or_create_kek_metadata(self, plugin_inst, tenant, kek_repo):
        # Find or create a key encryption key.
        full_plugin_name = utils.generate_fullname_for(plugin_inst)
        kek_datum = kek_repo.find_or_create_kek_metadata(tenant,
                                                         full_plugin_name)

        # Bind to the plugin's key management.
        # TODO: Does this need to be in a critical section? Should the bind
        #   operation just be declared idempotent in the plugin contract?
        kek_metadata = plugin_mod.KEKMetadata(kek_datum)
        if not kek_datum.bind_completed:
            plugin_inst.bind_kek_metadata(kek_metadata)
            plugin_mod.indicate_bind_completed(kek_metadata, kek_datum)
            kek_repo.save(kek_datum)

        return (kek_datum, kek_metadata)
