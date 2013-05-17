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
    """Raised when requested decripted format is not
    available in any active plugin."""
    def __init__(self, accept):
        super(CryptoAcceptNotSupportedException, self).__init__(
            _("Crypto Accept of '{0}' not supported").format(accept)
        )
        self.accept = accept


class CryptoNoSecretOrDataException(BarbicanException):
    """Raised when secret information is not available for the specified
    secret mime-type."""
    def __init__(self, mime_type):
        super(CryptoNoSecretOrDataException, self).__init__(
            _('No secret information available for '
              'Mime Type of {0}').format(mime_type)
        )
        self.mime_type = mime_type


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

    def encrypt(self, unencrypted, secret, tenant):
        """Delegates encryption to active plugins."""
        for ext in self.extensions:
            if ext.obj.supports(secret.mime_type):
                return ext.obj.encrypt(unencrypted, secret, tenant)
        else:
            raise CryptoMimeTypeNotSupportedException(secret.mime_type)

    def decrypt(self, accept, secret, tenant):
        """Delegates decryption to active plugins."""
        if not secret or not secret.encrypted_data:
            raise CryptoNoSecretOrDataException(accept)

        plain_text = None
        for ext in self.extensions:
            if ext.obj.supports(accept):
                plain_text = ext.obj.decrypt(accept, secret, tenant)
                break
        else:
            raise CryptoAcceptNotSupportedException(accept)

        if not plain_text:
            raise CryptoNoSecretOrDataException(accept)

        return plain_text

    def generate_data_encryption_key(self, secret, tenant):
        """
        Delegates generating a data-encryption key to active plugins.

        Note that this key can be used by clients for their encryption
        processes. This generated key is then be encrypted via
        the plug-in key encryption process, and that encrypted datum
        is then returned from this method.
        """
        for ext in self.extensions:
            if ext.obj.supports(secret.mime_type):
                # TODO: Call plugin's key generation processes.
                #   Note: It could be the *data* key to generate (for the
                #   secret algo type) uses a different plug in than that
                #   used to encrypted the key.
                data_key = ext.obj.create(secret.mime_type)
                return ext.obj.encrypt(data_key, secret, tenant)
        else:
            raise CryptoMimeTypeNotSupportedException(secret.mime_type)

    def supports(self, secret, tenant):
        """Tests if at least one plug-in supports the secret type."""
        for ext in self.extensions:
            if ext.obj.supports(secret.mime_type):
                return True
        else:
            raise CryptoMimeTypeNotSupportedException(secret.mime_type)
