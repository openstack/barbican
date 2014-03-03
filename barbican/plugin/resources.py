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


def get_transport_key_model(key_spec, repos, transport_key_needed):
    key_model = None
    if transport_key_needed:
        # get_plugin_store() will throw an exception if no suitable
        # plugin with transport key is found
        store_plugin = secret_store.SecretStorePluginManager(). \
            get_plugin_store(key_spec=key_spec, transport_key_needed=True)
        plugin_name = utils.generate_fullname_for(store_plugin)

        key_repo = repos.transport_key_repo
        key_model = key_repo.get_latest_transport_key(plugin_name)

        if not key_model or not store_plugin.is_transport_key_current(
                key_model.transport_key):
            # transport key does not exist or is not current.
            # need to get a new transport key
            transport_key = store_plugin.get_transport_key()
            new_key_model = models.TransportKey(plugin_name, transport_key)
            key_model = key_repo.create_from(new_key_model)
    return key_model


def get_plugin_name_and_transport_key(repos, transport_key_id):
    plugin_name = None
    transport_key = None
    if transport_key_id is not None:
        transport_key_model = repos.transport_key_repo.get(
            entity_id=transport_key_id)
        if transport_key_model is None:
            raise ValueError("Invalid transport key ID provided")

        plugin_name = transport_key_model.plugin_name
        if plugin_name is None:
            raise ValueError("Invalid plugin name for transport key")

        transport_key = transport_key_model.transport_key

    return plugin_name, transport_key


def store_secret(unencrypted_raw, content_type_raw, content_encoding,
                 spec, secret_model, tenant_model, repos,
                 transport_key_needed=False,
                 transport_key_id=None):
    """Store a provided secret into secure backend."""

    # Create a secret model is one isn't provided.
    #   Note: For one-step secret stores, the model is not provided. For
    #   two-step secrets, the secret entity is already created and should then
    #   be passed into this function.
    if not secret_model:
        secret_model = models.Secret(spec)
    elif _secret_already_has_stored_data(secret_model):
        raise ValueError('Secret already has encrypted data stored for it.')

    # Create a KeySpec to find a plugin that will support storing the secret
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    mode=spec.get('mode'))

    # If there is no secret data to store, then just create Secret entity and
    #   leave. A subsequent call to this method should provide both the Secret
    #   entity created here *and* the secret data to store into it.
    if not unencrypted_raw:
        key_model = get_transport_key_model(key_spec,
                                            repos,
                                            transport_key_needed)

        _save_secret(secret_model, tenant_model, repos)
        return secret_model, key_model

    plugin_name, transport_key = get_plugin_name_and_transport_key(
        repos, transport_key_id)

    # Locate a suitable plugin to store the secret.
    store_plugin = secret_store.SecretStorePluginManager().\
        get_plugin_store(key_spec=key_spec, plugin_name=plugin_name)

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
    secret_type = secret_store.KeyAlgorithm().get_secret_type(key_spec.alg)
    secret_dto = secret_store.SecretDTO(type=secret_type,
                                        secret=unencrypted,
                                        key_spec=key_spec,
                                        content_type=content_type,
                                        transport_key=transport_key)
    secret_metadata = store_plugin.store_secret(secret_dto, context)

    # Save secret and metadata.
    _save_secret(secret_model, tenant_model, repos)
    _save_secret_metadata(secret_model, secret_metadata, store_plugin,
                          content_type, repos)

    return secret_model, None


def get_secret(requesting_content_type, secret_model, tenant_model,
               twsk=None, transport_key=None):
    tr.analyze_before_decryption(requesting_content_type)

    # Construct metadata dict from data model.
    #   Note: Must use the dict/tuple format for py2.6 usage.
    secret_metadata = dict((k, v.value) for (k, v) in
                           secret_model.secret_store_metadata.items())

    if twsk is not None:
        secret_metadata['trans_wrapped_session_key'] = twsk
        secret_metadata['transport_key'] = transport_key

    # Locate a suitable plugin to store the secret.
    retrieve_plugin = secret_store.SecretStorePluginManager()\
        .get_plugin_retrieve_delete(secret_metadata.get('plugin_name'))

    # Retrieve the secret.
    #TODO(john-wood-w) Remove the SecretStoreContext once repository factory
    #  and unit test patch work is completed.
    context = secret_store.SecretStoreContext(secret_model=secret_model,
                                              tenant_model=tenant_model)
    secret_dto = retrieve_plugin.get_secret(secret_metadata, context)

    if twsk is not None:
        del secret_metadata['transport_key']
        del secret_metadata['trans_wrapped_session_key']

    # Denormalize the secret.
    return tr.denormalize_after_decryption(secret_dto.secret,
                                           requesting_content_type)


def get_transport_key_id_for_retrieval(secret_model):
    """Return a transport key ID for retrieval if the plugin supports it."""

    secret_metadata = dict((k, v.value) for (k, v) in
                           secret_model.secret_store_metadata.items())

    retrieve_plugin = secret_store.SecretStorePluginManager()\
        .get_plugin_retrieve_delete(secret_metadata.get('plugin_name'))

    transport_key_id = retrieve_plugin.get_transport_key()
    return transport_key_id


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


def generate_asymmetric_secret(spec, content_type,
                               tenant_model, repos):
    raise NotImplementedError("Feature not yet implemented")


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
