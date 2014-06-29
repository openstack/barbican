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

from barbican.common import utils
from barbican.model import models
from barbican.plugin.interface import secret_store
from barbican.plugin.util import translations as tr


def store_secret(unencrypted_raw, content_type_raw, content_encoding,
                 spec, secret_model, tenant_model,
                 repos):
    """Store a provided secret into secure backend."""

    # Create a secret model is one isn't provided.
    #   Note: For one-step secret stores, the model is not provided. For
    #   two-step secrets, the secret entity is already created and should then
    #   be passed into this function.
    if not secret_model:
        secret_model = models.Secret(spec)
    elif _secret_already_has_stored_data(secret_model):
        raise ValueError('Secret already has encrypted data stored for it.')

    # If there is no secret data to store, then just create Secret entity and
    #   leave. A subsequent call to this method should provide both the Secret
    #   entity created here *and* the secret data to store into it.
    if not unencrypted_raw:
        _save_secret(secret_model, tenant_model, repos)
        return secret_model

    # Locate a suitable plugin to store the secret.
    store_plugin = secret_store.SecretStorePluginManager().get_plugin_store()

    # Normalize inputs prior to storage.
    #TODO(john-wood-w) Normalize all secrets to base64, so we don't have to
    #  pass in 'content' type to the store_secret() call below.
    unencrypted, content_type = tr.normalize_before_encryption(
        unencrypted_raw, content_type_raw, content_encoding,
        enforce_text_only=True)

    # Store the secret securely.
    #TODO(john-wood-w) Remove the SecretStoreContext once repository factory
    #  and unit test patch work is completed.
    context = secret_store.SecretStoreContext(secret_model=secret_model,
                                              tenant_model=tenant_model,
                                              repos=repos)
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    mode=spec.get('mode'))
    secret_dto = secret_store.SecretDTO(None, unencrypted, key_spec,
                                        content_type)
    secret_metadata = store_plugin.store_secret(secret_dto, context)

    # Save secret and metadata.
    _save_secret(secret_model, tenant_model, repos)
    _save_secret_metadata(secret_model, secret_metadata, store_plugin,
                          content_type, repos)

    return secret_model


def get_secret(requesting_content_type, secret_model, tenant_model):
    tr.analyze_before_decryption(requesting_content_type)

    # Construct metadata dict from data model.
    #   Note: Must use the dict/tuple format for py2.6 usage.
    secret_metadata = dict((k, v.value) for (k, v) in
                           secret_model.secret_store_metadata.items())

    # Locate a suitable plugin to store the secret.
    retrieve_plugin = secret_store.SecretStorePluginManager()\
        .get_plugin_retrieve_delete(secret_metadata.get('plugin_name'))

    # Retrieve the secret.
    #TODO(john-wood-w) Remove the SecretStoreContext once repository factory
    #  and unit test patch work is completed.
    context = secret_store.SecretStoreContext(secret_model=secret_model,
                                              tenant_model=tenant_model)
    secret_dto = retrieve_plugin.get_secret(secret_metadata, context)

    # Denormalize the secret.
    return tr.denormalize_after_decryption(secret_dto.secret,
                                           requesting_content_type)


def generate_secret(spec, content_type,
                    tenant_model, repos):
    """Generate a secret and store into a secure backend."""

    # Locate a suitable plugin to store the secret.
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    mode=spec.get('mode'))
    generate_plugin = secret_store.SecretStorePluginManager()\
        .get_plugin_generate(key_spec)

    # Create secret model to eventually save metadata to.
    secret_model = models.Secret(spec)

    # Generate the secret.
    #TODO(john-wood-w) Remove the SecretStoreContext once repository factory
    #  and unit test patch work is completed.
    context = secret_store.SecretStoreContext(content_type=content_type,
                                              secret_model=secret_model,
                                              tenant_model=tenant_model,
                                              repos=repos)

    #TODO(john-wood-w) Replace with single 'generate_key()' call once
    #  asymmetric and symmetric generation is combined.
    secret_metadata = generate_plugin.\
        generate_symmetric_key(key_spec, context)

    # Save secret and metadata.
    _save_secret(secret_model, tenant_model, repos)
    _save_secret_metadata(secret_model, secret_metadata, generate_plugin,
                          content_type, repos)

    return secret_model


def delete_secret(secret_model, project_id, repos):
    """Remove a secret from secure backend."""

    # Construct metadata dict from data model.
    #   Note: Must use the dict/tuple format for py2.6 usage.
    secret_metadata = dict((k, v.value) for (k, v) in
                           secret_model.secret_store_metadata.items())

    # Locate a suitable plugin to delete the secret from.
    delete_plugin = secret_store.SecretStorePluginManager()\
        .get_plugin_retrieve_delete(secret_metadata.get('plugin_name'))

    # Delete the secret from plugin storage.
    delete_plugin.delete_secret(secret_metadata)

    # Delete the secret from data model.
    repos.secret_repo.delete_entity_by_id(entity_id=secret_model.id,
                                          keystone_id=project_id)


def _save_secret_metadata(secret_model, secret_metadata,
                          store_plugin, content_type, repos):
    """Add secret metadata to a secret."""

    if not secret_metadata:
        secret_metadata = dict()

    secret_metadata['plugin_name'] = utils\
        .generate_fullname_for(store_plugin)

    secret_metadata['content_type'] = content_type

    repos.secret_meta_repo.save(secret_metadata, secret_model)


def _save_secret(secret_model, tenant_model, repos):
    """Save a Secret entity."""

    # Create Secret entities in data store.
    if not secret_model.id:
        repos.secret_repo.create_from(secret_model)
        new_assoc = models.TenantSecret()
        new_assoc.tenant_id = tenant_model.id
        new_assoc.secret_id = secret_model.id
        new_assoc.role = "admin"
        new_assoc.status = models.States.ACTIVE
        repos.tenant_secret_repo.create_from(new_assoc)
    else:
        repos.secret_repo.save(secret_model)


def _secret_already_has_stored_data(secret_model):
    if not secret_model:
        return False
    return secret_model.encrypted_data or secret_model.secret_store_metadata
