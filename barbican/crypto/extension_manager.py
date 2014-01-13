# Copyright (c) 2013-2014 Rackspace, Inc.
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

import base64

from oslo.config import cfg
from stevedore import named

from barbican.common import exception
from barbican.common import utils
from barbican.crypto import mime_types
from barbican.crypto import plugin as plugin_mod
from barbican.model import models
from barbican.openstack.common import gettextutils as u


CONF = cfg.CONF
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


class CryptoContentTypeNotSupportedException(exception.BarbicanException):
    """Raised when support for payload content type is not available."""
    def __init__(self, content_type):
        super(CryptoContentTypeNotSupportedException, self).__init__(
            u._("Crypto Content Type "
                "of '{0}' not supported").format(content_type)
        )
        self.content_type = content_type


class CryptoContentEncodingNotSupportedException(exception.BarbicanException):
    """Raised when support for payload content encoding is not available."""
    def __init__(self, content_encoding):
        super(CryptoContentEncodingNotSupportedException, self).__init__(
            u._("Crypto Content-Encoding of '{0}' not supported").format(
                content_encoding)
        )
        self.content_encoding = content_encoding


class CryptoAcceptNotSupportedException(exception.BarbicanException):
    """Raised when requested decrypted content-type is not available."""
    def __init__(self, accept):
        super(CryptoAcceptNotSupportedException, self).__init__(
            u._("Crypto Accept of '{0}' not supported").format(accept)
        )
        self.accept = accept


class CryptoAlgorithmNotSupportedException(exception.BarbicanException):
    """Raised when support for an algorithm is not available."""
    def __init__(self, algorithm):
        super(CryptoAlgorithmNotSupportedException, self).__init__(
            u._("Crypto algorithm of '{0}' not supported").format(
                algorithm)
        )
        self.algorithm = algorithm


class CryptoPayloadDecodingError(exception.BarbicanException):
    """Raised when payload could not be decoded."""
    def __init__(self):
        super(CryptoPayloadDecodingError, self).__init__(
            u._("Problem decoding payload")
        )


class CryptoSupportedPluginNotFound(exception.BarbicanException):
    """
    Raised when no plugins are found that support the requested
    operation.
    """
    message = "Crypto plugin not found for requested operation."


class CryptoPluginNotFound(exception.BarbicanException):
    """Raised when no plugins are installed."""
    message = u._("Crypto plugin not found.")


class CryptoNoPayloadProvidedException(exception.BarbicanException):
    """Raised when secret information is not provided."""
    def __init__(self):
        super(CryptoNoPayloadProvidedException, self).__init__(
            u._('No secret information provided to encrypt.')
        )


class CryptoNoSecretOrDataFoundException(exception.BarbicanException):
    """Raised when secret information could not be located."""
    def __init__(self, secret_id):
        super(CryptoNoSecretOrDataFoundException, self).__init__(
            u._('No secret information located for '
                'secret {0}').format(secret_id)
        )
        self.secret_id = secret_id


class CryptoContentEncodingMustBeBase64(exception.BarbicanException):
    """Raised when encoding must be base64."""
    def __init__(self):
        super(CryptoContentEncodingMustBeBase64, self).__init__(
            u._("Encoding type must be 'base64' for text-based payloads.")
        )


class CryptoKEKBindingException(exception.BarbicanException):
    """Raised when the bind_kek_metadata method from a plugin returns None."""
    def __init__(self, plugin_name=u._('Unknown')):
        super(CryptoKEKBindingException, self).__init__(
            u._('Failed to bind kek metadata for '
                'plugin: {0}').format(plugin_name)
        )
        self.plugin_name = plugin_name


class CryptoGeneralException(exception.BarbicanException):
    """Raised when a system fault has occurred."""
    def __init__(self, reason=u._('Unknown')):
        super(CryptoGeneralException, self).__init__(
            u._('Problem seen during crypto processing - '
                'Reason: {0}').format(reason)
        )
        self.reason = reason


def normalize_before_encryption(unencrypted, content_type, content_encoding,
                                enforce_text_only=False):
    """Normalize unencrypted prior to plugin encryption processing."""
    if not unencrypted:
        raise CryptoNoPayloadProvidedException()

    # Validate and normalize content-type.
    normalized_mime = mime_types.normalize_content_type(content_type)
    if not mime_types.is_supported(normalized_mime):
        raise CryptoContentTypeNotSupportedException(content_type)

    # Process plain-text type.
    if normalized_mime in mime_types.PLAIN_TEXT:
        # normalize text to binary string
        unencrypted = unencrypted.encode('utf-8')

    # Process binary type.
    elif normalized_mime in mime_types.BINARY:
        # payload has to be decoded
        if mime_types.is_base64_processing_needed(content_type,
                                                  content_encoding):
            try:
                unencrypted = base64.b64decode(unencrypted)
            except TypeError:
                raise CryptoPayloadDecodingError()
        elif enforce_text_only:
            # For text-based protocols (such as the one-step secret POST),
            #   only 'base64' encoding is possible/supported.
            raise CryptoContentEncodingMustBeBase64()
        elif content_encoding:
            # Unsupported content-encoding request.
            raise CryptoContentEncodingNotSupportedException(content_encoding)

    else:
        raise CryptoContentTypeNotSupportedException(content_type)

    return unencrypted, normalized_mime


def analyze_before_decryption(content_type):
    """Determine support for desired content type."""
    if not mime_types.is_supported(content_type):
        raise CryptoAcceptNotSupportedException(content_type)


def denormalize_after_decryption(unencrypted, content_type):
    """Translate the decrypted data into the desired content type."""
    # Process plain-text type.
    if content_type in mime_types.PLAIN_TEXT:
        # normalize text to binary string
        try:
            unencrypted = unencrypted.decode('utf-8')
        except UnicodeDecodeError:
            raise CryptoAcceptNotSupportedException(content_type)

    # Process binary type.
    elif content_type not in mime_types.BINARY:
        raise CryptoGeneralException(
            u._("Unexpected content-type: '{0}'").format(content_type))

    return unencrypted


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

    def encrypt(self, unencrypted, content_type, content_encoding,
                secret, tenant, kek_repo, enforce_text_only=False):
        """Delegates encryption to first plugin that supports it."""

        if len(self.extensions) < 1:
            raise CryptoPluginNotFound()

        for ext in self.extensions:
            if ext.obj.supports(plugin_mod.PluginSupportTypes.ENCRYPT_DECRYPT):
                encrypting_plugin = ext.obj
                break
        else:
            raise CryptoSupportedPluginNotFound()

        unencrypted, content_type = normalize_before_encryption(
            unencrypted, content_type, content_encoding,
            enforce_text_only=enforce_text_only)

        # Find or create a key encryption key metadata.
        kek_datum, kek_meta_dto = self._find_or_create_kek_objects(
            encrypting_plugin, tenant, kek_repo)

        # Create an encrypted datum instance and add the encrypted cypher text.
        datum = models.EncryptedDatum(secret, kek_datum)
        datum.content_type = content_type
        datum.cypher_text, datum.kek_meta_extended = encrypting_plugin.encrypt(
            unencrypted, kek_meta_dto, tenant.keystone_id
        )

        # Convert binary data into a text-based format.
        #TODO(jwood) Figure out by storing binary (BYTEA) data in Postgres
        #  isn't working.
        datum.cypher_text = base64.b64encode(datum.cypher_text)

        return datum

    def decrypt(self, content_type, secret, tenant):
        """Delegates decryption to active plugins."""

        if not secret or not secret.encrypted_data:
            raise CryptoNoSecretOrDataFoundException(secret.id)

        analyze_before_decryption(content_type)

        for ext in self.extensions:
            decrypting_plugin = ext.obj
            for datum in secret.encrypted_data:
                if self._plugin_supports(decrypting_plugin,
                                         datum.kek_meta_tenant):
                    # wrap the KEKDatum instance in our DTO
                    kek_meta_dto = plugin_mod.KEKMetaDTO(datum.kek_meta_tenant)

                    # Convert from text-based storage format to binary.
                    #TODO(jwood) Figure out by storing binary (BYTEA) data in
                    #  Postgres isn't working.
                    encrypted = base64.b64decode(datum.cypher_text)

                    # Decrypt the secret.
                    unencrypted = decrypting_plugin \
                        .decrypt(encrypted,
                                 kek_meta_dto,
                                 datum.kek_meta_extended,
                                 tenant.keystone_id)

                    # Denormalize the decrypted info per request.
                    return denormalize_after_decryption(unencrypted,
                                                        content_type)
        else:
            raise CryptoPluginNotFound()

    def generate_data_encryption_key(self, secret, content_type, tenant,
                                     kek_repo):
        """Delegates generating a key to the first supported plugin.

        Note that this key can be used by clients for their encryption
        processes. This generated key is then be encrypted via
        the plug-in key encryption process, and that encrypted datum
        is then returned from this method.
        """
        if len(self.extensions) < 1:
            raise CryptoPluginNotFound()

        generation_type = self._determine_type(secret.algorithm)
        for ext in self.extensions:
            if ext.obj.supports(generation_type, secret.algorithm):
                encrypting_plugin = ext.obj
                break
        else:
            raise CryptoSupportedPluginNotFound()

        # Create the secret.

        data_key = encrypting_plugin.create(secret.bit_length,
                                            generation_type,
                                            secret.algorithm,
                                            secret.mode)

        # Encrypt the secret.
        return self.encrypt(data_key, content_type, None, secret, tenant,
                            kek_repo)

    def _determine_type(self, algorithm):
        """Determines the type (symmetric only for now) based on algorithm"""
        symmetric_algs = plugin_mod.PluginSupportTypes.SYMMETRIC_ALGORITHMS
        if algorithm.lower() in symmetric_algs:
            return plugin_mod.PluginSupportTypes.SYMMETRIC_KEY_GENERATION
        else:
            raise CryptoAlgorithmNotSupportedException(algorithm)

    def _plugin_supports(self, plugin_inst, kek_metadata_tenant):
        """Tests for plugin support.

        Tests if the supplied plugin supports operations on the supplied
        key encryption key (KEK) metadata.

        :param plugin_inst: The plugin instance to test.
        :param kek_metadata: The KEK metadata to test.
        :return: True if the plugin can support operations on the KEK metadata.

        """
        plugin_name = utils.generate_fullname_for(plugin_inst)
        return plugin_name == kek_metadata_tenant.plugin_name

    def _find_or_create_kek_objects(self, plugin_inst, tenant, kek_repo):
        # Find or create a key encryption key.
        full_plugin_name = utils.generate_fullname_for(plugin_inst)
        kek_datum = kek_repo.find_or_create_kek_datum(tenant,
                                                      full_plugin_name)

        # Bind to the plugin's key management.
        # TODO(jwood): Does this need to be in a critical section? Should the
        # bind operation just be declared idempotent in the plugin contract?
        kek_meta_dto = plugin_mod.KEKMetaDTO(kek_datum)
        if not kek_datum.bind_completed:
            kek_meta_dto = plugin_inst.bind_kek_metadata(kek_meta_dto)

            # By contract, enforce that plugins return a
            # (typically modified) DTO.
            if kek_meta_dto is None:
                raise CryptoKEKBindingException(full_plugin_name)

            plugin_mod.indicate_bind_completed(kek_meta_dto, kek_datum)
            kek_repo.save(kek_datum)

        return kek_datum, kek_meta_dto
