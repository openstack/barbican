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

import abc

from oslo_config import cfg
import six
from stevedore import named

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin.util import utils as plugin_utils


_SECRET_STORE = None

CONF = config.new_config()
DEFAULT_PLUGIN_NAMESPACE = 'barbican.secretstore.plugin'
DEFAULT_PLUGINS = ['store_crypto']

store_opt_group = cfg.OptGroup(name='secretstore',
                               title='Secret Store Plugin Options')
store_opts = [
    cfg.StrOpt('namespace',
               default=DEFAULT_PLUGIN_NAMESPACE,
               help=u._('Extension namespace to search for plugins.')
               ),
    cfg.MultiStrOpt('enabled_secretstore_plugins',
                    default=DEFAULT_PLUGINS,
                    help=u._('List of secret store plugins to load.')
                    )
]
CONF.register_group(store_opt_group)
CONF.register_opts(store_opts, group=store_opt_group)
config.parse_args(CONF)


class SecretStorePluginNotFound(exception.BarbicanHTTPException):
    """Raised when no plugins are installed."""

    client_message = u._("No plugin was found that could support your request")
    status_code = 400

    def __init__(self, plugin_name=None):
        if plugin_name:
            message = u._('Secret store plugin "{name}"'
                          ' not found.').format(name=plugin_name)
        else:
            message = u._("Secret store plugin not found.")
        super(SecretStorePluginNotFound, self).__init__(message)


class SecretStoreSupportedPluginNotFound(exception.BarbicanHTTPException):
    """Raised if no plugins are found that support the requested operation."""

    client_message = u._("Secret store supported plugin not found.")
    status_code = 400

    def __init__(self, plugin_name=None):
        message = u._("Secret store plugin not found for requested operation.")
        super(SecretStoreSupportedPluginNotFound, self).__init__(
            message)


class SecretContentTypeNotSupportedException(exception.BarbicanHTTPException):
    """Raised when support for payload content type is not available."""

    status_code = 400

    def __init__(self, content_type):
        super(SecretContentTypeNotSupportedException, self).__init__(
            u._("A Content-Type of '{content_type}' for secrets is "
                "not supported").format(
                    content_type=content_type)
        )
        self.content_type = content_type
        self.client_message = u._(
            "content-type of '{content_type}' not supported").format(
                content_type=content_type)


class SecretContentEncodingNotSupportedException(
        exception.BarbicanHTTPException):
    """Raised when support for payload content encoding is not available."""
    status_code = 400

    def __init__(self, content_encoding):
        super(SecretContentEncodingNotSupportedException, self).__init__(
            u._("Secret Content-Encoding of '{content_encoding}' "
                "not supported").format(
                    content_encoding=content_encoding)
        )
        self.content_encoding = content_encoding
        self.client_message = u._(
            "content-encoding of '{content_encoding}' not supported").format(
                content_encoding=content_encoding)


class SecretNoPayloadProvidedException(exception.BarbicanException):
    """Raised when secret information is not provided."""
    def __init__(self):
        super(SecretNoPayloadProvidedException, self).__init__(
            u._('No secret information provided to encrypt.')
        )


class SecretContentEncodingMustBeBase64(exception.BarbicanHTTPException):
    """Raised when encoding must be base64."""

    client_message = u._("Text-based binary secret payloads must "
                         "specify a content-encoding of 'base64'")
    status_code = 400

    def __init__(self):
        super(SecretContentEncodingMustBeBase64, self).__init__(
            u._("Encoding type must be 'base64' for text-based payloads.")
        )


class SecretGeneralException(exception.BarbicanException):
    """Raised when a system fault has occurred."""
    def __init__(self, reason=u._('Unknown')):
        super(SecretGeneralException, self).__init__(
            u._('Problem seen during crypto processing - '
                'Reason: {reason}').format(reason=reason)
        )
        self.reason = reason


class SecretPayloadDecodingError(exception.BarbicanHTTPException):
    """Raised when payload could not be decoded."""

    client_message = u._("Problem decoding payload")
    status_code = 400

    def __init__(self):
        super(SecretPayloadDecodingError, self).__init__(
            u._("Problem decoding payload")
        )


class SecretAcceptNotSupportedException(exception.BarbicanException):
    """Raised when requested decrypted content-type is not available."""
    def __init__(self, accept):
        super(SecretAcceptNotSupportedException, self).__init__(
            u._("Secret Accept of '{accept}' not supported").format(
                accept=accept)
        )
        self.accept = accept


class SecretNotFoundException(exception.BarbicanHTTPException):
    """Raised when secret information could not be located."""

    client_message = u._("Not Found. Sorry but your secret is in another "
                         "castle")
    status_code = 404

    def __init__(self):
        super(SecretNotFoundException, self).__init__(
            u._('No secret information found'))


class SecretAlgorithmNotSupportedException(exception.BarbicanHTTPException):
    """Raised when support for an algorithm is not available."""

    client_message = u._("Requested algorithm is not supported")
    status_code = 400

    def __init__(self, algorithm):
        super(SecretAlgorithmNotSupportedException, self).__init__(
            u._("Secret algorithm of '{algorithm}' not supported").format(
                algorithm=algorithm)
        )
        self.algorithm = algorithm


class SecretStorePluginsNotConfigured(exception.BarbicanException):
    """Raised when there are no secret store plugins configured."""
    def __init__(self):
        super(SecretStorePluginsNotConfigured, self).__init__(
            u._('No secret store plugins have been configured')
        )


class StorePluginNotAvailableOrMisconfigured(exception.BarbicanException):
    """Raised when a plugin that was previously used can not be found."""
    def __init__(self, plugin_name):
        super(StorePluginNotAvailableOrMisconfigured, self).__init__(
            u._("The requested Store Plugin {plugin_name} is not "
                "currently available. This is probably a server "
                "misconfiguration.").format(
                plugin_name=plugin_name)
        )
        self.plugin_name = plugin_name


class SecretType(object):

    """Constant to define the symmetric key type.

    Used by getSecret to retrieve a symmetric key.
    """
    SYMMETRIC = "symmetric"
    """Constant to define the public key type. Used by getSecret to retrieve a
    public key.
    """
    PUBLIC = "public"
    """Constant to define the private key type. Used by getSecret to retrieve a
    private key.
    """
    PRIVATE = "private"
    """Constant to define the passphrase type. Used by getSecret to retrieve a
    passphrase."""
    PASSPHRASE = "passphrase"
    """Constant to define the certificate type. Used by getSecret to retrieve a
    certificate."""
    CERTIFICATE = "certificate"
    """Constant to define the opaque date type. Used by getSecret to retrieve
    opaque data. Opaque data can be any kind of data. This data type signals to
    Barbican to just store the information and do not worry about the format or
    encoding. This is the default type if no type is specified by the user."""
    OPAQUE = "opaque"


class KeyAlgorithm(object):

    """Constant for the Diffie Hellman algorithm."""
    DIFFIE_HELLMAN = "diffie_hellman"
    """Constant for the DSA algorithm."""
    DSA = "dsa"
    """Constant for the RSA algorithm."""
    RSA = "rsa"
    """Constant for the Elliptic Curve algorithm."""
    EC = "ec"
    """Constant for the HMACSHA1 algorithm."""
    HMACSHA1 = "hmacsha1"
    """Constant for the HMACSHA256 algorithm."""
    HMACSHA256 = "hmacsha256"
    """Constant for the HMACSHA384 algorithm."""
    HMACSHA384 = "hmacsha384"
    """Constant for the HMACSHA512 algorithm."""
    HMACSHA512 = "hmacsha512"
    """List of asymmetric algorithms"""
    ASYMMETRIC_ALGORITHMS = [DIFFIE_HELLMAN, DSA, RSA, EC]
    """Constant for the AES algorithm."""
    AES = "aes"
    """Constant for the DES algorithm."""
    DES = "des"
    """Constant for the DESede (triple-DES) algorithm."""
    DESEDE = "desede"
    """List of symmetric algorithms"""
    SYMMETRIC_ALGORITHMS = [AES, DES, DESEDE, HMACSHA1,
                            HMACSHA256, HMACSHA384, HMACSHA512]


class KeySpec(object):
    """This object specifies the algorithm and bit length for a key."""

    def __init__(self, alg=None, bit_length=None, mode=None, passphrase=None):
        """Creates a new KeySpec.

        :param alg:algorithm for the key
        :param bit_length:bit length of the key
        :param mode:algorithm mode for the key
        :param passphrase:passphrase for the private_key
        """
        self.alg = alg
        self.bit_length = bit_length
        self.mode = mode  # TODO(john-wood-w) Paul, is 'mode' required?
        self.passphrase = passphrase


class SecretDTO(object):
    """This object is a secret data transfer object (DTO).

    This object encapsulates a key and attributes about the key. The attributes
    include a KeySpec that contains the algorithm and bit length. The
    attributes also include information on the encoding of the key.
    """

    # TODO(john-wood-w) Remove 'content_type' once secret normalization work is
    #  completed.
    def __init__(self, type, secret, key_spec, content_type,
                 transport_key=None):
        """Creates a new SecretDTO.

        The secret is stored in the secret parameter. In the future this
        DTO may include compression and key wrapping information.

        :param type: SecretType for secret
        :param secret: secret, as a base64-encoded string
        :param key_spec: KeySpec key specifications
        :param content_type: Content type of the secret, one of MIME
               types such as 'text/plain' or 'application/octet-stream'
        :param transport_key: presence of this parameter indicates that the
               secret has been encrypted using a transport key.  The transport
               key is a base64 encoded x509 transport certificate.
        """
        self.type = type or SecretType.OPAQUE
        self.secret = secret
        self.key_spec = key_spec
        self.content_type = content_type
        self.transport_key = transport_key


class AsymmetricKeyMetadataDTO(object):
    """This DTO encapsulates metadata(s) for asymmetric key components.

    These components are private_key_meta, public_key_meta and passphrase_meta.
    """

    def __init__(self, private_key_meta=None,
                 public_key_meta=None,
                 passphrase_meta=None):
        """Constructor for AsymmetricKeyMetadataDTO

        :param private_key_meta: private key metadata
        :param public_key_meta: public key metadata
        :param passphrase_meta: passphrase key metadata
        """
        self.private_key_meta = private_key_meta
        self.public_key_meta = public_key_meta
        self.passphrase_meta = passphrase_meta


@six.add_metaclass(abc.ABCMeta)
class SecretStoreBase(object):

    @abc.abstractmethod
    def generate_symmetric_key(self, key_spec):
        """Generate a new symmetric key and store it.

        Generates a new symmetric key and stores it in the secret store.
        A dictionary is returned that contains metadata about the newly created
        symmetric key. The dictionary of metadata is stored by Barbican and
        passed into other methods to aid the plugins. This can be useful for
        plugins that generate a unique ID in the external data store and use it
        to retrieve the key in the future. The returned dictionary may be empty
        if the SecretStore does not require it.

        :param key_spec: KeySpec that contains details on the type of key to
            generate
        :returns: an optional dictionary containing metadata about the key
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_asymmetric_key(self, key_spec):
        """Generate a new asymmetric key pair and store it.

        Generates a new asymmetric key pair and stores it in the secret
        store. An object of type AsymmetricKeyMetadataDTO will be returned
        containing attributes of metadata for newly created key pairs.
        The metadata is stored by Barbican and passed into other methods
        to aid the plugins. This can be useful for plugins that generate
        a unique ID in the external data store and use it to retrieve the
        key pairs in the future.

        :param key_spec: KeySpec that contains details on the type of key to
            generate
        :returns: An object of type AsymmetricKeyMetadataDTO containing
            metadata about the key pair.
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def store_secret(self, secret_dto):
        """Stores a key.

        The SecretDTO contains the bytes of the secret and properties of the
        secret.  The SecretStore retrieves the secret bytes, stores them, and
        returns a dictionary of metadata about the secret.  This can be
        useful for plugins that generate a unique ID in the external data
        store and use it to retrieve the secret in the future. The returned
        dictionary may be empty if the SecretStore does not require it.

        :param secret_dto: SecretDTO for secret
        :returns: an optional dictionary containing metadata about the secret
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def get_secret(self, secret_type, secret_metadata):
        """Retrieves a secret from the secret store.

        Retrieves a secret from the secret store and returns a SecretDTO that
        contains the secret.

        The secret_metadata parameter is the metadata returned from one of the
        generate or store methods. This data is used by the plugins to retrieve
        the key.

        The secret_type parameter may be useful for secret stores to know the
        expected format of the secret. For instance if the type is
        SecretDTO.PRIVATE then a PKCS8 structure is returned. This way secret
        stores do not need to manage the secret type on their own.

        :param secret_type: secret type
        :param secret_metadata: secret metadata
        :returns: SecretDTO that contains secret
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_supports(self, key_spec):
        """Returns a boolean indicating if the secret type is supported.

        This checks if the algorithm and bit length are supported by the
        generate methods. This is useful to call before calling
        generate_symmetric_key or generate_asymetric_key to see if the key type
        is supported before trying to generate it.

        :param key_spec: KeySpec that contains details on the algorithm and bit
            length
        :returns: boolean indicating if the algorithm is supported
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def delete_secret(self, secret_metadata):
        """Deletes a secret from the secret store.

        Deletes a secret from a secret store. It can no longer be referenced
        after this call.

        :param secret_metadata: secret_metadata
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def store_secret_supports(self, key_spec):
        """Returns a boolean indicating if the secret can be stored.

        Checks if the secret store can store the secret, give the attributes
        of the secret in the KeySpec. For example, some plugins may need to
        know the attributes in order to store the secret, but other plugins
        may be able to store the secret as a blob if no attributes are given.

        :param key_spec: KeySpec for the secret
        :returns: a boolean indicating if the secret can be stored
        """
        raise NotImplementedError  # pragma: no cover

    def get_transport_key(self):
        """Gets a transport key.

        Returns the current valid transport key associated with this plugin.
        The transport key is expected to be a base64 encoded x509 certificate
        containing a public key.  Admins are responsible for deleting old keys
        from the database using the DELETE method on the TransportKey resource.

        By default, returns None.  Plugins that support transport key
        wrapping should override this method.
        """
        return None

    def is_transport_key_current(self, transport_key):
        """Determines if the provided transport key is the current valid key

        Returns true if the transport key is the current valid transport key.
        If the key is not valid, then barbican core will request a new
        transport key from the plugin.

        Returns False by default.  Plugins that support transport key wrapping
        should override this method.
        """
        return False


def _enforce_extensions_configured(plugin_related_function):
    def _check_plugins_configured(self, *args, **kwargs):
        if not self.extensions:
            raise SecretStorePluginsNotConfigured()
        return plugin_related_function(self, *args, **kwargs)
    return _check_plugins_configured


class SecretStorePluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_args=(), invoke_kwargs={}):
        super(SecretStorePluginManager, self).__init__(
            conf.secretstore.namespace,
            conf.secretstore.enabled_secretstore_plugins,
            invoke_on_load=False,  # Defer creating plugins to utility below.
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

        plugin_utils.instantiate_plugins(
            self, invoke_args, invoke_kwargs)

    @_enforce_extensions_configured
    def get_plugin_store(self, key_spec, plugin_name=None,
                         transport_key_needed=False):
        """Gets a secret store plugin.

        :param: plugin_name: set to plugin_name to get specific plugin
        :param: key_spec: KeySpec of key that will be stored
        :param: transport_key_needed: set to True if a transport
        key is required.
        :returns: SecretStoreBase plugin implementation
        """
        active_plugins = plugin_utils.get_active_plugins(self)

        if plugin_name is not None:
            for plugin in active_plugins:
                if utils.generate_fullname_for(plugin) == plugin_name:
                    return plugin
            raise SecretStorePluginNotFound(plugin_name)

        if not transport_key_needed:
            for plugin in active_plugins:
                if plugin.store_secret_supports(key_spec):
                    return plugin

        else:
            for plugin in active_plugins:
                if (plugin.get_transport_key() is not None and
                        plugin.store_secret_supports(key_spec)):
                    return plugin

        raise SecretStoreSupportedPluginNotFound()

    @_enforce_extensions_configured
    def get_plugin_retrieve_delete(self, plugin_name):
        """Gets a secret retrieve/delete plugin.

        If this function is being called, it is because we are trying to
        retrieve or delete an already stored secret. Thus, the plugin name is
        actually gotten from the plugin metadata that has already been stored
        in the database. So, in this case, if this plugin is not available,
        this might be due to a server misconfiguration.

        :returns: SecretStoreBase plugin implementation
        :raises: StorePluginNotAvailableOrMisconfigured: If the plugin wasn't
                 found it's because the plugin parameters were not properly
                 configured on the database side.
        """

        for plugin in plugin_utils.get_active_plugins(self):
            if utils.generate_fullname_for(plugin) == plugin_name:
                return plugin
        raise StorePluginNotAvailableOrMisconfigured(plugin_name)

    @_enforce_extensions_configured
    def get_plugin_generate(self, key_spec):
        """Gets a secret generate plugin.

        :param key_spec: KeySpec that contains details on the type of key to
        generate
        :returns: SecretStoreBase plugin implementation
        """

        for plugin in plugin_utils.get_active_plugins(self):
            if plugin.generate_supports(key_spec):
                return plugin
        raise SecretStoreSupportedPluginNotFound()


def get_manager():
    global _SECRET_STORE
    if not _SECRET_STORE:
        _SECRET_STORE = SecretStorePluginManager()
    return _SECRET_STORE
