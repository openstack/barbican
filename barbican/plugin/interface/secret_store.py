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
import six

from oslo.config import cfg
from stevedore import named

from barbican.common import exception
from barbican.common import utils
from barbican.openstack.common import gettextutils as u


CONF = cfg.CONF
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


class SecretStorePluginNotFound(exception.BarbicanException):
    """Raised when no plugins are installed."""
    message = u._("Secret store plugin not found.")


class SecretStoreSupportedPluginNotFound(exception.BarbicanException):
    """Raised when no plugins are found that support the requested
    operation.
    """
    message = "Secret store plugin not found for requested operation."


class SecretContentTypeNotSupportedException(exception.BarbicanException):
    """Raised when support for payload content type is not available."""
    def __init__(self, content_type):
        super(SecretContentTypeNotSupportedException, self).__init__(
            u._("Secret Content Type "
                "of '{0}' not supported").format(content_type)
        )
        self.content_type = content_type


class SecretContentEncodingNotSupportedException(exception.BarbicanException):
    """Raised when support for payload content encoding is not available."""
    def __init__(self, content_encoding):
        super(SecretContentEncodingNotSupportedException, self).__init__(
            u._("Secret Content-Encoding of '{0}' not supported").format(
                content_encoding)
        )
        self.content_encoding = content_encoding


class SecretNoPayloadProvidedException(exception.BarbicanException):
    """Raised when secret information is not provided."""
    def __init__(self):
        super(SecretNoPayloadProvidedException, self).__init__(
            u._('No secret information provided to encrypt.')
        )


class SecretContentEncodingMustBeBase64(exception.BarbicanException):
    """Raised when encoding must be base64."""
    def __init__(self):
        super(SecretContentEncodingMustBeBase64, self).__init__(
            u._("Encoding type must be 'base64' for text-based payloads.")
        )


class SecretGeneralException(exception.BarbicanException):
    """Raised when a system fault has occurred."""
    def __init__(self, reason=u._('Unknown')):
        super(SecretGeneralException, self).__init__(
            u._('Problem seen during crypto processing - '
                'Reason: {0}').format(reason)
        )
        self.reason = reason


class SecretPayloadDecodingError(exception.BarbicanException):
    """Raised when payload could not be decoded."""
    def __init__(self):
        super(SecretPayloadDecodingError, self).__init__(
            u._("Problem decoding payload")
        )


class SecretAcceptNotSupportedException(exception.BarbicanException):
    """Raised when requested decrypted content-type is not available."""
    def __init__(self, accept):
        super(SecretAcceptNotSupportedException, self).__init__(
            u._("Secret Accept of '{0}' not supported").format(accept)
        )
        self.accept = accept


class SecretNotFoundException(exception.BarbicanException):
    """Raised when secret information could not be located."""
    def __init__(self):
        super(SecretNotFoundException, self).__init__(
            u._('No secret information found')
        )


class SecretAlgorithmNotSupportedException(exception.BarbicanException):
    """Raised when support for an algorithm is not available."""
    def __init__(self, algorithm):
        super(SecretAlgorithmNotSupportedException, self).__init__(
            u._("Secret algorithm of '{0}' not supported").format(
                algorithm)
        )
        self.algorithm = algorithm


class SecretType(object):

    """Constant to define the symmetric key type. Used by getSecret to retrieve
    a symmetric key.
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


class KeyAlgorithm(object):

    """Constant for the Diffie Hellman algorithm."""
    DIFFIE_HELLMAN = "diffie_hellman"
    """Constant for the DSA algorithm."""
    DSA = "dsa"
    """Constant for the RSA algorithm."""
    RSA = "rsa"
    """Constant for the Elliptic Curve algorithm."""
    EC = "ec"

    """Constant for the AES algorithm."""
    AES = "aes"
    """Constant for the DES algorithm."""
    DES = "des"
    """Constant for the DESede (triple-DES) algorithm."""
    DESEDE = "desede"


class KeySpec(object):
    """This object specifies the algorithm and bit length for a key."""

    def __init__(self, alg=None, bit_length=None, mode=None):
        """Creates a new KeySpec.

        :param alg:algorithm for the key
        :param bit_length:bit length of the key
        :param mode:algorithm mode for the key
        """
        self.alg = alg
        self.bit_length = bit_length
        self.mode = mode  # TODO(john-wood-w) Paul, is 'mode' required?


class SecretDTO(object):
    """This object is a secret data transfer object (DTO). This object
    encapsulates a key and attributes about the key. The attributes include a
    KeySpec that contains the algorithm and bit length. The attributes also
    include information on the encoding of the key.
    """

    #TODO(john-wood-w) Remove 'content_type' once secret normalization work is
    #  completed.
    def __init__(self, type, secret, key_spec, content_type):
        """Creates a new SecretDTO.

        The secret is stored in the secret parameter. In the future this
        DTO may include compression and key wrapping information.

        :param type: SecretType for secret
        :param secret: secret, as a base64-encoded string
        :param key_spec: KeySpec key specifications
        :param content_type: Content type of the secret, one of MIME
               types such as 'text/plain' or 'application/octet-stream'
        """
        self.type = type
        self.secret = secret
        self.key_spec = key_spec
        self.content_type = content_type


#TODO(john-wood-w) Remove this class once repository factory work is
#  completed.
class SecretStoreContext(object):
    """Context for secret store plugins.

    Some plugins implementations (such as the crypto implementation) might
    require access to core Barbican resources such as datastore repositories.
    This object provides access to such storage.
    """
    def __init__(self, **kwargs):
        if kwargs:
            for k, v in kwargs.items():
                setattr(self, k, v)


@six.add_metaclass(abc.ABCMeta)
class SecretStoreBase(object):

    #TODO(john-wood-w) Remove 'context' once repository factory and secret
    #  normalization work is completed.
    #TODO(john-wood-w) Combine generate_symmetric_key() and
    #  generate_asymmetric_key() into one method: generate_key(), that will
    #  return a dict with this structure:
    #    { SecretType.xxxxx: {secret-meta dict}
    #  So for symmetric keys, this would look like:
    #    { SecretType.SYMMETRIC: {secret-meta dict}
    #  And for asymmetric keys:
    #    { SecretType.PUBLIC: {secret-meta for public},
    #      SecretType.PRIVATE: {secret-meta for private}}
    @abc.abstractmethod
    def generate_symmetric_key(self, key_spec, context):
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
        :param context: SecretStoreContext for secret
        :returns: a dictionary that contains metadata about the key
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_asymmetric_key(self, key_spec, context):
        """Generate a new asymmetric key and store it.

        Generates a new asymmetric key and stores it in the secret store.
        A dictionary is returned that contains metadata about the newly created
        key pairs. The dictionary of metadata is stored by Barbican and
        passed into other methods to aid the plugins. This can be useful for
        plugins that generate a unique ID in the external data store and use it
        to retrieve the key in the future. The returned dictionary may be empty
        if the SecretStore does not require it.

        :param key_spec: KeySpec that contains details on the type of key to
        generate
        :param context: SecretStoreContext for secret
        :returns: a dictionary that contains metadata about the key
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def store_secret(self, secret_dto, context):
        """Stores a key.

        The SecretDTO contains the bytes of the secret and properties of the
        secret.  The SecretStore retrieves the secret bytes, stores them, and
        returns a dictionary of metadata about the secret.  This can be
        useful for plugins that generate a unique ID in the external data
        store and use it to retrieve the secret in the future. The returned
        dictionary may be empty if the SecretStore does not require it.

        :param secret_dto: SecretDTO for secret
        :param context: SecretStoreContext for secret
        :returns: a dictionary that contains metadata about the secret
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def get_secret(self, secret_metadata, context):
        """Retrieves a secret from the secret store.

        Retrieves a secret from the secret store and returns a SecretDTO that
        contains the secret.

        The secret_metadata parameter is the metadata returned from one of the
        generate or store methods. This data is used by the plugins to retrieve
        the key.

        :param secret_metadata: secret metadata
        :param context: SecretStoreContext for secret
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


class SecretStorePluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_on_load=True,
                 invoke_args=(), invoke_kwargs={}):
        super(SecretStorePluginManager, self).__init__(
            conf.secretstore.namespace,
            conf.secretstore.enabled_secretstore_plugins,
            invoke_on_load=invoke_on_load,
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

    def get_plugin_store(self):
        """Gets a secret store plugin.

        :returns: SecretStoreBase plugin implementation
        """

        if len(self.extensions) < 1:
            raise SecretStorePluginNotFound()

        return self.extensions[0].obj

    def get_plugin_retrieve_delete(self, plugin_name):
        """Gets a secret retrieve/delete plugin.

        :returns: SecretStoreBase plugin implementation
        """

        if len(self.extensions) < 1:
            raise SecretStorePluginNotFound()

        for ext in self.extensions:
            if utils.generate_fullname_for(ext.obj) == plugin_name:
                retrieve_delete_plugin = ext.obj
                break
        else:
            raise SecretStoreSupportedPluginNotFound()

        return retrieve_delete_plugin

    def get_plugin_generate(self, key_spec):
        """Gets a secret generate plugin.

        :param key_spec: KeySpec that contains details on the type of key to
        generate
        :returns: SecretStoreBase plugin implementation
        """

        if len(self.extensions) < 1:
            raise SecretStorePluginNotFound()

        for ext in self.extensions:
            if ext.obj.generate_supports(key_spec):
                generate_plugin = ext.obj
                break
        else:
            raise SecretStoreSupportedPluginNotFound()

        return generate_plugin
