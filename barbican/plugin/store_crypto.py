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
from barbican.plugin.crypto import crypto
from barbican.plugin.crypto import manager
from barbican.plugin.interface import secret_store as sstore

CONF = cfg.CONF


class StoreCryptoAdapterPlugin(sstore.SecretStoreBase):
    """Secret store plugin adapting to 'crypto' devices as backend.

    HSM-style 'crypto' devices perform encryption/decryption processing but
    do not actually store the encrypted information, unlike other 'secret
    store' plugins that do provide storage. Hence, this adapter bridges
    between these two plugin styles, providing Barbican persistence services
    as needed to store information.
    """

    def __init__(self):
        super(StoreCryptoAdapterPlugin, self).__init__()

    def store_secret(self, secret_dto, context):
        """Store a secret.

        Returns a dict with the relevant metadata (which in this case is just
        the key_id
        """

        # Find HSM-style 'crypto' plugin.
        encrypting_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            crypto.PluginSupportTypes.ENCRYPT_DECRYPT
        )

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = self._find_or_create_kek_objects(
            encrypting_plugin, context.tenant_model, context.repos.kek_repo)

        encrypt_dto = crypto.EncryptDTO(secret_dto.secret)

        # Enhance the context with content_type, This is needed to build
        # datum_model to store
        if not getattr(context, 'content_type', ''):
            context.content_type = secret_dto.content_type

        # Create an encrypted datum instance and add the encrypted cyphertext.
        response_dto = encrypting_plugin.encrypt(
            encrypt_dto, kek_meta_dto, context.tenant_model.keystone_id
        )
        # Convert binary data into a text-based format.
        # TODO(jwood) Figure out by storing binary (BYTEA) data in Postgres
        #  isn't working.
        self._store_secret_and_datum(context,
                                     context.secret_model,
                                     kek_datum_model,
                                     response_dto)

        return None

    def get_secret(self, secret_metadata, context):
        """Retrieve a secret."""
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
        # TODO(jwood) Figure out by storing binary (BYTEA) data in
        #  Postgres isn't working.
        encrypted = base64.b64decode(datum_model.cypher_text)
        decrypt_dto = crypto.DecryptDTO(encrypted)

        # Decrypt the secret.
        secret = decrypting_plugin.decrypt(decrypt_dto,
                                           kek_meta_dto,
                                           datum_model.kek_meta_extended,
                                           context.tenant_model.keystone_id)
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

        Returns a metadata object that can be used for retrieving the secret.
        """

        # Find HSM-style 'crypto' plugin.
        plugin_type = self._determine_generation_type(key_spec.alg)
        if crypto.PluginSupportTypes.SYMMETRIC_KEY_GENERATION != plugin_type:
            raise sstore.SecretAlgorithmNotSupportedException(key_spec.alg)
        generating_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            plugin_type,
            key_spec.alg,
            key_spec.bit_length,
            key_spec.mode)

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = self._find_or_create_kek_objects(
            generating_plugin, context.tenant_model, context.repos.kek_repo)

        # Create an encrypted datum instance and add the created cypher text.
        generate_dto = crypto.GenerateDTO(key_spec.alg,
                                          key_spec.bit_length,
                                          key_spec.mode, None)
        # Create the encrypted meta.
        response_dto = generating_plugin.generate_symmetric(
            generate_dto, kek_meta_dto, context.tenant_model.keystone_id)

        # Convert binary data into a text-based format.
        # TODO(jwood) Figure out by storing binary (BYTEA) data in Postgres
        #  isn't working.
        self._store_secret_and_datum(context,
                                     context.secret_model,
                                     kek_datum_model,
                                     response_dto)

        return None

    def generate_asymmetric_key(self, key_spec, context):
        """Generates an asymmetric key.

        Returns a AsymmetricKeyMetadataDTO object containing
        metadata(s) for asymmetric key components. The metadata
        can be used to retrieve individual components of
        asymmetric key pair.
        """

        plugin_type = self._determine_generation_type(key_spec.alg)
        if crypto.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION != plugin_type:
            raise sstore.SecretAlgorithmNotSupportedException(key_spec.alg)

        generating_plugin = manager.PLUGIN_MANAGER.get_plugin_store_generate(
            plugin_type, key_spec.alg, key_spec.bit_length, None)

        # Find or create a key encryption key metadata.
        kek_datum_model, kek_meta_dto = self._find_or_create_kek_objects(
            generating_plugin, context.tenant_model, context.repos.kek_repo)

        generate_dto = crypto.GenerateDTO(key_spec.alg,
                                          key_spec.bit_length,
                                          None, key_spec.passphrase)

        # Create the encrypted meta.
        private_key_dto, public_key_dto, passwd_dto = (
            generating_plugin.generate_asymmetric(
                generate_dto, kek_meta_dto, context.tenant_model.keystone_id
            )
        )

        self._store_secret_and_datum(context,
                                     context.private_secret_model,
                                     kek_datum_model,
                                     private_key_dto)

        self._store_secret_and_datum(context,
                                     context.public_secret_model,
                                     kek_datum_model,
                                     public_key_dto)

        if passwd_dto:
            self._store_secret_and_datum(context,
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
                sstore.KeyAlgorithm().get_secret_type(key_spec.alg))

    def store_secret_supports(self, key_spec):
        """Key storage supported?

        Specifies whether the plugin supports storage of the secret given
        the attributes included in the KeySpec
        """
        return True

    def _find_or_create_kek_objects(self, plugin_inst, tenant_model, kek_repo):
        # Find or create a key encryption key.
        full_plugin_name = utils.generate_fullname_for(plugin_inst)
        kek_datum_model = kek_repo.find_or_create_kek_datum(tenant_model,
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

            self._indicate_bind_completed(kek_meta_dto, kek_datum_model)
            kek_repo.save(kek_datum_model)

        return kek_datum_model, kek_meta_dto

    def _store_secret_and_datum(self, context,
                                secret_model,
                                kek_datum_model,
                                generated_dto):
        # Create Secret entities in data store.
        if not secret_model.id:
            context.repos.secret_repo.create_from(secret_model)
            new_assoc = models.TenantSecret()
            new_assoc.tenant_id = context.tenant_model.id
            new_assoc.secret_id = secret_model.id
            new_assoc.role = "admin"
            new_assoc.status = models.States.ACTIVE
            context.repos.tenant_secret_repo.create_from(new_assoc)

        # setup and store encrypted datum
        datum_model = models.EncryptedDatum(secret_model, kek_datum_model)
        datum_model.content_type = context.content_type
        datum_model.cypher_text = base64.b64encode(generated_dto.cypher_text)
        datum_model.kek_meta_extended = generated_dto.kek_meta_extended
        datum_model.secret_id = secret_model.id
        context.repos.datum_repo.create_from(datum_model)

    def _indicate_bind_completed(self, kek_meta_dto, kek_datum):
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

    # TODO(john-wood-w) Move this to the more generic secret_store.py?
    def _determine_generation_type(self, algorithm):
        """Determines the type based on the given algorithm.

        For now this is either symmetric or asymmetric.
        """
        symmetric_algs = crypto.PluginSupportTypes.SYMMETRIC_ALGORITHMS
        asymmetric_algs = crypto.PluginSupportTypes.ASYMMETRIC_ALGORITHMS
        if algorithm.lower() in symmetric_algs:
            return crypto.PluginSupportTypes.SYMMETRIC_KEY_GENERATION
        elif algorithm.lower() in asymmetric_algs:
            return crypto.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION
        else:
            raise sstore.SecretAlgorithmNotSupportedException(algorithm)
