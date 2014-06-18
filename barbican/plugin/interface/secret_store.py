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


class KeyFormat(object):

    """Key format that indicates that key value is a bytearray of the raw bytes
    of the string.
    """
    RAW = "raw"
    """PKCS #1 encoding format."""
    PKCS1 = "pkcs1"
    """PKCS #8 encoding format."""
    PKCS8 = "pkcs8"
    """X.509 encoding format."""
    X509 = "x509"


class KeySpec(object):
    """This object specifies the algorithm and bit length for a key."""

    def __init__(self, alg, bit_length):
        """Creates a new KeySpec.

        :param alg:algorithm for the key
        :param bit_length:bit length of the key
        """
        self.alg = alg
        self.bit_length = bit_length


class SecretDTO(object):
    """This object is a secret data transfer object (DTO). This object
    encapsulates a key and attributes about the key. The attributes include a
    KeySpec that contains the algorithm and bit length. The attributes also
    include information on the format and encoding of the key.
    """

    def __init__(self, type, format, secret, key_spec):
        """Creates a new SecretDTO.

        The secret is stored in the secret parameter. The format parameter
        indicates the format of the bytes for the secret. In the future this
        DTO may include compression and key wrapping information.

        :param type: SecretType for secret
        :param format: KeyFormat key format
        :param secret: secret
        :param key_spec: KeySpec key specifications
        """
        self.type = type
        self.format = format
        self.secret = secret
        self.key_spec = key_spec


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
        :returns: a dictionary that contains metadata about the key
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_asymmetric_key(self, key_spec):
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
        :returns: a dictionary that contains metadata about the key
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
        :returns: a dictionary that contains metadata about the secret
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def get_secret(self, secret_metadata):
        """Retrieves a secret from the secret store.

        Retrieves a secret from the secret store and returns a SecretDTO that
        contains the secret.

        The secret_metadata parameter is the metadata returned from one of the
        generate or store methods. This data is used by the plugins to retrieve
        the key.

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
