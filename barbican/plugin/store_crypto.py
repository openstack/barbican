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

from barbican.common import utils
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.crypto import crypto
from barbican.plugin.crypto import manager
from barbican.plugin.interface import secret_store as sstore

CONF = cfg.CONF


class StoreCryptoContext(object):
    """Context for crypto-adapter secret store plugins.

    This context object allows access to core Barbican resources such as
    datastore models.
    """
    def __init__(
            self,
            project_model,
            secret_model=None,
            private_secret_model=None,
            public_secret_model=None,
            passphrase_secret_model=None,
            content_type=None):
        self.secret_model = secret_model
        self.private_secret_model = private_secret_model
        self.public_secret_model = public_secret_model
        self.passphrase_secret_model = passphrase_secret_model
        self.project_model = project_model
        self.content_type = content_type


class StoreCryptoAdapterPlugin(object):
    """Secret store plugin adapting to 'crypto' devices as backend.

    HSM-style 'crypto' devices perform encryption/decryption processing but
    do not actually store the encrypted information, unlike other 'secret
    store' plugins that do provide storage. Hence, this adapter bridges
    between these two plugin styles, providing Barbican persistence services
    as needed to store information.

    Note that this class does not inherit from SecretStoreBase, as it also
    requires access to lower-level datastore entities such as KEKDatum. This
    additional information is passed in via the 'context' parameter.
    """

    def __init__(self):
        super(StoreCryptoAdapterPlugin, self).__init__()

    def store_secret(self, secret_dto, context):
        """Store a secret.

        :param secret_dto: SecretDTO for secret
        :param context: StoreCryptoContext for secret
        :returns: an optional dictionary containing metadata about the secret
        """

        # Find HSM-style 'crypto' plugin.
        encrypting_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            crypto.PluginSupportTypes.ENCRYPT_DECRYPT
        )

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = _find_or_create_kek_objects(
            encrypting_plugin, context.project_model)

        encrypt_dto = crypto.EncryptDTO(secret_dto.secret)

        # Enhance the context with content_type, This is needed to build
        # datum_model to store
        if not context.content_type:
            context.content_type = secret_dto.content_type

        # Create an encrypted datum instance and add the encrypted cyphertext.
        response_dto = encrypting_plugin.encrypt(
            encrypt_dto, kek_meta_dto, context.project_model.keystone_id
        )

        # Convert binary data into a text-based format.
        _store_secret_and_datum(
            context, context.secret_model, kek_datum_model, response_dto)

        return None

    def get_secret(self, secret_metadata, context):
        """Retrieve a secret.

        :param secret_metadata: secret metadata
        :param context: StoreCryptoContext for secret
        :returns: SecretDTO that contains secret
        """
        if (not context.secret_model or
                not context.secret_model.encrypted_data):
            raise sstore.SecretNotFoundException()

        # TODO(john-wood-w) Need to revisit 1 to many datum relationship.
        datum_model = context.secret_model.encrypted_data[0]

        # Find HSM-style 'crypto' plugin.
        decrypting_plugin = manager.PLUGIN_MANAGER.get_plugin_retrieve(
            datum_model.kek_meta_tenant.plugin_name)

        # wrap the KEKDatum instance in our DTO
        kek_meta_dto = crypto.KEKMetaDTO(datum_model.kek_meta_tenant)

        # Convert from text-based storage format to binary.
        encrypted = base64.b64decode(datum_model.cypher_text)
        decrypt_dto = crypto.DecryptDTO(encrypted)

        # Decrypt the secret.
        secret = decrypting_plugin.decrypt(decrypt_dto,
                                           kek_meta_dto,
                                           datum_model.kek_meta_extended,
                                           context.project_model.keystone_id)
        key_spec = sstore.KeySpec(alg=context.secret_model.algorithm,
                                  bit_length=context.secret_model.bit_length,
                                  mode=context.secret_model.mode)

        return sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                secret, key_spec,
                                datum_model.content_type)

    def delete_secret(self, secret_metadata):
        """Delete a secret."""
        pass

    def generate_symmetric_key(self, key_spec, context):
        """Generate a symmetric key.

        :param key_spec: KeySpec that contains details on the type of key to
        generate
        :param context: StoreCryptoContext for secret
        :returns: a dictionary that contains metadata about the key
        """

        # Find HSM-style 'crypto' plugin.
        plugin_type = _determine_generation_type(key_spec.alg)
        if crypto.PluginSupportTypes.SYMMETRIC_KEY_GENERATION != plugin_type:
            raise sstore.SecretAlgorithmNotSupportedException(key_spec.alg)
        generating_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            plugin_type,
            key_spec.alg,
            key_spec.bit_length,
            key_spec.mode)

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = _find_or_create_kek_objects(
            generating_plugin, context.project_model)

        # Create an encrypted datum instance and add the created cypher text.
        generate_dto = crypto.GenerateDTO(key_spec.alg,
                                          key_spec.bit_length,
                                          key_spec.mode, None)
        # Create the encrypted meta.
        response_dto = generating_plugin.generate_symmetric(
            generate_dto, kek_meta_dto, context.project_model.keystone_id)

        # Convert binary data into a text-based format.
        _store_secret_and_datum(
            context, context.secret_model, kek_datum_model, response_dto)

        return None

    def generate_asymmetric_key(self, key_spec, context):
        """Generates an asymmetric key.

        Returns a AsymmetricKeyMetadataDTO object containing
        metadata(s) for asymmetric key components. The metadata
        can be used to retrieve individual components of
        asymmetric key pair.
        """

        plugin_type = _determine_generation_type(key_spec.alg)
        if crypto.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION != plugin_type:
            raise sstore.SecretAlgorithmNotSupportedException(key_spec.alg)

        generating_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            plugin_type, key_spec.alg, key_spec.bit_length, None)

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = _find_or_create_kek_objects(
            generating_plugin, context.project_model)

        generate_dto = crypto.GenerateDTO(key_spec.alg,
                                          key_spec.bit_length,
                                          None, key_spec.passphrase)

        # Create the encrypted meta.
        private_key_dto, public_key_dto, passwd_dto = (
            generating_plugin.generate_asymmetric(
                generate_dto, kek_meta_dto, context.project_model.keystone_id
            )
        )

        _store_secret_and_datum(
            context,
            context.private_secret_model,
            kek_datum_model,
            private_key_dto)

        _store_secret_and_datum(
            context,
            context.public_secret_model,
            kek_datum_model,
            public_key_dto)

        if key_spec.passphrase and passwd_dto:
            _store_secret_and_datum(
                context,
                context.passphrase_secret_model,
                kek_datum_model,
                passwd_dto)

        return sstore.AsymmetricKeyMetadataDTO()

    def generate_supports(self, key_spec):
        """Key generation supported?

        Specifies whether the plugin supports key generation with the
        given key_spec.
        """
        return (key_spec and
                (key_spec.alg.lower() in
                 sstore.KeyAlgorithm.ASYMMETRIC_ALGORITHMS
                 or key_spec.alg.lower() in
                 sstore.KeyAlgorithm.SYMMETRIC_ALGORITHMS))

    def store_secret_supports(self, key_spec):
        """Key storage supported?

        Specifies whether the plugin supports storage of the secret given
        the attributes included in the KeySpec
        """
        return True


def _determine_generation_type(algorithm):
    """Determines the type (symmetric and asymmetric for now)
    based on algorithm
    """
    if not algorithm:
        raise sstore.SecretAlgorithmNotSupportedException(algorithm)

    symmetric_algs = crypto.PluginSupportTypes.SYMMETRIC_ALGORITHMS
    asymmetric_algs = crypto.PluginSupportTypes.ASYMMETRIC_ALGORITHMS
    if algorithm.lower() in symmetric_algs:
        return crypto.PluginSupportTypes.SYMMETRIC_KEY_GENERATION
    elif algorithm.lower() in asymmetric_algs:
        return crypto.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION
    else:
        raise sstore.SecretAlgorithmNotSupportedException(algorithm)


def _find_or_create_kek_objects(plugin_inst, project_model):
    kek_repo = repositories.get_kek_datum_repository()

    # Find or create a key encryption key.
    full_plugin_name = utils.generate_fullname_for(plugin_inst)
    kek_datum_model = kek_repo.find_or_create_kek_datum(project_model,
                                                        full_plugin_name)

    # Bind to the plugin's key management.
    # TODO(jwood): Does this need to be in a critical section? Should the
    # bind operation just be declared idempotent in the plugin contract?
    kek_meta_dto = crypto.KEKMetaDTO(kek_datum_model)
    if not kek_datum_model.bind_completed:
        kek_meta_dto = plugin_inst.bind_kek_metadata(kek_meta_dto)

        # By contract, enforce that plugins return a
        # (typically modified) DTO.
        if kek_meta_dto is None:
            raise crypto.CryptoKEKBindingException(full_plugin_name)

        _indicate_bind_completed(kek_meta_dto, kek_datum_model)
        kek_repo.save(kek_datum_model)

    return kek_datum_model, kek_meta_dto


def _store_secret_and_datum(
        context, secret_model, kek_datum_model, generated_dto):

    # Create Secret entities in data store.
    if not secret_model.id:
        repositories.get_secret_repository().create_from(secret_model)
        new_assoc = models.TenantSecret()
        new_assoc.tenant_id = context.project_model.id
        new_assoc.secret_id = secret_model.id
        new_assoc.role = "admin"
        new_assoc.status = models.States.ACTIVE
        repositories.get_project_secret_repository().create_from(new_assoc)

    # setup and store encrypted datum
    datum_model = models.EncryptedDatum(secret_model, kek_datum_model)
    datum_model.content_type = context.content_type
    datum_model.cypher_text = base64.b64encode(generated_dto.cypher_text)
    datum_model.kek_meta_extended = generated_dto.kek_meta_extended
    datum_model.secret_id = secret_model.id
    repositories.get_encrypted_datum_repository().create_from(
        datum_model)


def _indicate_bind_completed(kek_meta_dto, kek_datum):
    """Updates the supplied kek_datum instance

    Updates the the kek_datum per the contents of the supplied
    kek_meta_dto instance. This function is typically used once plugins
    have had a chance to bind kek_meta_dto to their crypto systems.

    :param kek_meta_dto:
    :param kek_datum:
    :return: None

    """
    kek_datum.bind_completed = True
    kek_datum.algorithm = kek_meta_dto.algorithm
    kek_datum.bit_length = kek_meta_dto.bit_length
    kek_datum.mode = kek_meta_dto.mode
    kek_datum.plugin_meta = kek_meta_dto.plugin_meta
