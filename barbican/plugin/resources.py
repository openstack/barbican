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
from barbican.plugin import store_crypto
from barbican.plugin.util import translations as tr


def get_transport_key_model(key_spec, repos, transport_key_needed):
    key_model = None
    if transport_key_needed:
        # get_plugin_store() will throw an exception if no suitable
        # plugin with transport key is found
        plugin_manager = secret_store.SecretStorePluginManager()
        store_plugin = plugin_manager.get_plugin_store(
            key_spec=key_spec, transport_key_needed=True)
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
                 spec, secret_model, project_model, repos,
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
    key_spec = None
    if spec:
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

        _save_secret(secret_model, project_model, repos)
        return secret_model, key_model

    plugin_name, transport_key = get_plugin_name_and_transport_key(
        repos, transport_key_id)

    # Locate a suitable plugin to store the secret.
    plugin_manager = secret_store.SecretStorePluginManager()
    store_plugin = plugin_manager.get_plugin_store(
        key_spec=key_spec, plugin_name=plugin_name)

    # Normalize inputs prior to storage.
    # TODO(john-wood-w) Normalize all secrets to base64, so we don't have to
    #  pass in 'content' type to the store_secret() call below.
    unencrypted, content_type = tr.normalize_before_encryption(
        unencrypted_raw, content_type_raw, content_encoding,
        enforce_text_only=True)

    # Store the secret securely.
    # TODO(john-wood-w) Remove the SecretStoreContext once repository factory
    #  and unit test patch work is completed.
    secret_type = None
    if key_spec is not None:
        secret_type = secret_store.KeyAlgorithm().get_secret_type(key_spec.alg)
    secret_dto = secret_store.SecretDTO(type=secret_type,
                                        secret=unencrypted,
                                        key_spec=key_spec,
                                        content_type=content_type,
                                        transport_key=transport_key)
    secret_metadata = _store_secret(
        store_plugin, secret_dto, secret_model, project_model)

    # Save secret and metadata.
    _save_secret(secret_model, project_model, repos)
    _save_secret_metadata(secret_model, secret_metadata, store_plugin,
                          content_type, repos)

    return secret_model, None


def get_secret(requesting_content_type, secret_model, project_model, repos,
               twsk=None, transport_key=None):
    tr.analyze_before_decryption(requesting_content_type)

    # Construct metadata dict from data model.
    #   Note: Must use the dict/tuple format for py2.6 usage.
    secret_metadata = _get_secret_meta(secret_model, repos)

    if twsk is not None:
        secret_metadata['trans_wrapped_session_key'] = twsk
        secret_metadata['transport_key'] = transport_key

    # Locate a suitable plugin to store the secret.
    plugin_manager = secret_store.SecretStorePluginManager()
    retrieve_plugin = plugin_manager.get_plugin_retrieve_delete(
        secret_metadata.get('plugin_name'))

    # Retrieve the secret.
    secret_dto = _get_secret(
        retrieve_plugin, secret_metadata, secret_model, project_model)

    if twsk is not None:
        del secret_metadata['transport_key']
        del secret_metadata['trans_wrapped_session_key']

    # Denormalize the secret.
    return tr.denormalize_after_decryption(secret_dto.secret,
                                           requesting_content_type)


def get_transport_key_id_for_retrieval(secret_model, repos):
    """Return a transport key ID for retrieval if the plugin supports it."""

    secret_metadata = _get_secret_meta(secret_model, repos)

    plugin_manager = secret_store.SecretStorePluginManager()
    retrieve_plugin = plugin_manager.get_plugin_retrieve_delete(
        secret_metadata.get('plugin_name'))

    transport_key_id = retrieve_plugin.get_transport_key()
    return transport_key_id


def generate_secret(spec, content_type,
                    project_model, repos):
    """Generate a secret and store into a secure backend."""

    # Locate a suitable plugin to store the secret.
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    mode=spec.get('mode'))

    plugin_manager = secret_store.SecretStorePluginManager()
    generate_plugin = plugin_manager.get_plugin_generate(key_spec)

    # Create secret model to eventually save metadata to.
    secret_model = models.Secret(spec)

    # Generate the secret.
    secret_metadata = _generate_symmetric_key(
        generate_plugin, key_spec, secret_model, project_model, content_type)

    # Save secret and metadata.
    _save_secret(secret_model, project_model, repos)
    _save_secret_metadata(secret_model, secret_metadata, generate_plugin,
                          content_type, repos)

    return secret_model


def generate_asymmetric_secret(spec, content_type,
                               project_model, repos):
    """Generate an asymmetric secret and store into a secure backend."""
    # Locate a suitable plugin to store the secret.
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    passphrase=spec.get('passphrase'))

    plugin_manager = secret_store.SecretStorePluginManager()
    generate_plugin = plugin_manager.get_plugin_generate(key_spec)

    # Create secret models to eventually save metadata to.
    private_secret_model = models.Secret(spec)
    public_secret_model = models.Secret(spec)
    passphrase_secret_model = (models.Secret(spec)
                               if spec.get('passphrase') else None)

    # Generate the secret.
    asymmetric_meta_dto = _generate_asymmetric_key(
        generate_plugin,
        key_spec,
        private_secret_model,
        public_secret_model,
        passphrase_secret_model,
        project_model
    )

    # Save secret and metadata.
    _save_secret(private_secret_model, project_model, repos)
    _save_secret_metadata(private_secret_model,
                          asymmetric_meta_dto.private_key_meta,
                          generate_plugin,
                          content_type, repos)

    _save_secret(public_secret_model, project_model, repos)
    _save_secret_metadata(public_secret_model,
                          asymmetric_meta_dto.public_key_meta,
                          generate_plugin,
                          content_type, repos)

    if spec.get('passphrase'):
        _save_secret(passphrase_secret_model, project_model, repos)
        _save_secret_metadata(passphrase_secret_model,
                              asymmetric_meta_dto.passphrase_meta,
                              generate_plugin,
                              content_type, repos)

    # Now create container
    container_model = _save_container(spec, project_model, repos,
                                      private_secret_model,
                                      public_secret_model,
                                      passphrase_secret_model)

    return container_model


def delete_secret(secret_model, project_id, repos):
    """Remove a secret from secure backend."""

    # Construct metadata dict from data model.
    #   Note: Must use the dict/tuple format for py2.6 usage.
    secret_metadata = _get_secret_meta(secret_model, repos)

    # Locate a suitable plugin to delete the secret from.
    plugin_manager = secret_store.SecretStorePluginManager()
    delete_plugin = plugin_manager.get_plugin_retrieve_delete(
        secret_metadata.get('plugin_name'))

    # Delete the secret from plugin storage.
    delete_plugin.delete_secret(secret_metadata)

    # Delete the secret from data model.
    repos.secret_repo.delete_entity_by_id(entity_id=secret_model.id,
                                          keystone_id=project_id)


def _store_secret(store_plugin, secret_dto, secret_model, project_model):
    if isinstance(store_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            secret_model=secret_model)
        secret_metadata = store_plugin.store_secret(secret_dto, context)
    else:
        secret_metadata = store_plugin.store_secret(secret_dto)
    return secret_metadata


def _generate_symmetric_key(
        generate_plugin, key_spec, secret_model, project_model, content_type):
    if isinstance(generate_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            secret_model=secret_model,
            content_type=content_type)
        secret_metadata = generate_plugin.generate_symmetric_key(
            key_spec, context)
    else:
        secret_metadata = generate_plugin.generate_symmetric_key(key_spec)
    return secret_metadata


def _generate_asymmetric_key(
        generate_plugin,
        key_spec,
        private_secret_model,
        public_secret_model,
        passphrase_secret_model,
        project_model):
    if isinstance(generate_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            private_secret_model=private_secret_model,
            public_secret_model=public_secret_model,
            passphrase_secret_model=passphrase_secret_model)
        asymmetric_meta_dto = generate_plugin.generate_asymmetric_key(
            key_spec, context)
    else:
        asymmetric_meta_dto = generate_plugin.generate_asymmetric_key(key_spec)
    return asymmetric_meta_dto


def _get_secret(
        retrieve_plugin, secret_metadata, secret_model, project_model):
    if isinstance(retrieve_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            secret_model=secret_model)
        secret_dto = retrieve_plugin.get_secret(secret_metadata, context)
    else:
        secret_dto = retrieve_plugin.get_secret(secret_metadata)
    return secret_dto


def _get_secret_meta(secret_model, repos):
    if secret_model:
        return repos.secret_meta_repo.get_metadata_for_secret(
            secret_model.id)
    else:
        return dict()


def _save_secret_metadata(secret_model, secret_metadata,
                          store_plugin, content_type, repos):
    """Add secret metadata to a secret."""

    if not secret_metadata:
        secret_metadata = dict()

    secret_metadata['plugin_name'] = utils.generate_fullname_for(store_plugin)

    secret_metadata['content_type'] = content_type

    repos.secret_meta_repo.save(secret_metadata, secret_model)


def _save_secret(secret_model, project_model, repos):
    """Save a Secret entity."""

    # Create Secret entities in data store.
    if not secret_model.id:
        repos.secret_repo.create_from(secret_model)
        new_assoc = models.TenantSecret()
        new_assoc.tenant_id = project_model.id
        new_assoc.secret_id = secret_model.id
        new_assoc.role = "admin"
        new_assoc.status = models.States.ACTIVE
        repos.project_secret_repo.create_from(new_assoc)
    else:
        repos.secret_repo.save(secret_model)


def _secret_already_has_stored_data(secret_model):
    if not secret_model:
        return False
    return secret_model.encrypted_data or secret_model.secret_store_metadata


def _save_container(spec, project_model, repos, private_secret_model,
                    public_secret_model, passphrase_secret_model):
    container_model = models.Container()
    container_model.name = spec.get('name')
    container_model.type = spec.get('algorithm', '').lower()
    container_model.status = models.States.ACTIVE
    container_model.tenant_id = project_model.id
    repos.container_repo.create_from(container_model)

    # create container_secret for private_key
    _create_container_secret_association(repos, 'private_key',
                                         private_secret_model,
                                         container_model)

    # create container_secret for public_key
    _create_container_secret_association(repos, 'public_key',
                                         public_secret_model,
                                         container_model)

    if spec.get('passphrase'):
        # create container_secret for passphrase
        _create_container_secret_association(repos, 'private_key_passphrase',
                                             passphrase_secret_model,
                                             container_model)
    return container_model


def _create_container_secret_association(repos, assoc_name, secret_model,
                                         container_model):
    container_secret = models.ContainerSecret()
    container_secret.name = assoc_name
    container_secret.container_id = container_model.id
    container_secret.secret_id = secret_model.id
    repos.container_secret_repo.create_from(container_secret)
