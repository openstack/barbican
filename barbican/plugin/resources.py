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

from barbican.common import exception
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin.interface import secret_store
from barbican.plugin import store_crypto
from barbican.plugin.util import translations as tr


def _get_transport_key_model(key_spec, transport_key_needed, project_id):
    key_model = None
    if transport_key_needed:
        # get_plugin_store() will throw an exception if no suitable
        # plugin with transport key is found
        plugin_manager = secret_store.get_manager()
        store_plugin = plugin_manager.get_plugin_store(
            key_spec=key_spec, transport_key_needed=True,
            project_id=project_id)
        plugin_name = utils.generate_fullname_for(store_plugin)

        key_repo = repos.get_transport_key_repository()
        key_model = key_repo.get_latest_transport_key(plugin_name)

        if not key_model or not store_plugin.is_transport_key_current(
                key_model.transport_key):
            # transport key does not exist or is not current.
            # need to get a new transport key
            transport_key = store_plugin.get_transport_key()
            new_key_model = models.TransportKey(plugin_name, transport_key)
            key_model = key_repo.create_from(new_key_model)
    return key_model


def _get_plugin_name_and_transport_key(transport_key_id):
    plugin_name = None
    transport_key = None
    if transport_key_id is not None:
        transport_key_repo = repos.get_transport_key_repository()
        try:
            transport_key_model = transport_key_repo.get(
                entity_id=transport_key_id)
        except exception.NotFound:
            raise exception.ProvidedTransportKeyNotFound(str(transport_key_id))

        plugin_name = transport_key_model.plugin_name
        if plugin_name is None:
            raise ValueError("Invalid plugin name for transport key")

        transport_key = transport_key_model.transport_key

    return plugin_name, transport_key


def store_secret(unencrypted_raw, content_type_raw, content_encoding,
                 secret_model, project_model,
                 transport_key_needed=False,
                 transport_key_id=None):
    """Store a provided secret into secure backend."""
    if _secret_already_has_stored_data(secret_model):
        raise ValueError('Secret already has encrypted data stored for it.')

    # Create a KeySpec to find a plugin that will support storing the secret
    key_spec = secret_store.KeySpec(alg=secret_model.algorithm,
                                    bit_length=secret_model.bit_length,
                                    mode=secret_model.mode)

    # If there is no secret data to store, then just create Secret entity and
    #   leave. A subsequent call to this method should provide both the Secret
    #   entity created here *and* the secret data to store into it.
    if not unencrypted_raw:
        key_model = _get_transport_key_model(key_spec, transport_key_needed,
                                             project_id=project_model.id)

        _save_secret_in_repo(secret_model, project_model)
        return secret_model, key_model

    plugin_name, transport_key = _get_plugin_name_and_transport_key(
        transport_key_id)

    unencrypted, content_type = tr.normalize_before_encryption(
        unencrypted_raw, content_type_raw, content_encoding,
        secret_model.secret_type, enforce_text_only=True)

    plugin_manager = secret_store.get_manager()
    store_plugin = plugin_manager.get_plugin_store(key_spec=key_spec,
                                                   plugin_name=plugin_name,
                                                   project_id=project_model.id)

    secret_dto = secret_store.SecretDTO(type=secret_model.secret_type,
                                        secret=unencrypted,
                                        key_spec=key_spec,
                                        content_type=content_type,
                                        transport_key=transport_key)

    secret_metadata = _store_secret_using_plugin(store_plugin, secret_dto,
                                                 secret_model, project_model)
    _save_secret_in_repo(secret_model, project_model)
    _save_secret_metadata_in_repo(secret_model, secret_metadata, store_plugin,
                                  content_type)

    return secret_model, None


def get_secret(requesting_content_type, secret_model, project_model,
               twsk=None, transport_key=None):
    secret_metadata = _get_secret_meta(secret_model)

    # NOTE: */* is the pecan default meaning no content type sent in.  In this
    # case we should use the mime type stored in the metadata.
    if requesting_content_type == '*/*':
        requesting_content_type = secret_metadata['content_type']

    tr.analyze_before_decryption(requesting_content_type)

    if twsk is not None:
        secret_metadata['trans_wrapped_session_key'] = twsk
        secret_metadata['transport_key'] = transport_key

    # Locate a suitable plugin to store the secret.
    plugin_manager = secret_store.get_manager()
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


def get_transport_key_id_for_retrieval(secret_model):
    """Return a transport key ID for retrieval if the plugin supports it."""

    secret_metadata = _get_secret_meta(secret_model)

    plugin_manager = secret_store.get_manager()
    retrieve_plugin = plugin_manager.get_plugin_retrieve_delete(
        secret_metadata.get('plugin_name'))

    transport_key_id = retrieve_plugin.get_transport_key()
    return transport_key_id


def generate_secret(spec, content_type, project_model):
    """Generate a secret and store into a secure backend."""

    # Locate a suitable plugin to store the secret.
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    mode=spec.get('mode'))

    plugin_manager = secret_store.get_manager()
    generate_plugin = plugin_manager.get_plugin_generate(
        key_spec, project_id=project_model.id)

    # Create secret model to eventually save metadata to.
    secret_model = models.Secret(spec)
    secret_model['secret_type'] = secret_store.SecretType.SYMMETRIC

    # Generate the secret.
    secret_metadata = _generate_symmetric_key(
        generate_plugin, key_spec, secret_model, project_model, content_type)

    # Save secret and metadata.
    _save_secret_in_repo(secret_model, project_model)
    _save_secret_metadata_in_repo(secret_model, secret_metadata,
                                  generate_plugin, content_type)

    return secret_model


def generate_asymmetric_secret(spec, content_type, project_model):
    """Generate an asymmetric secret and store into a secure backend."""
    # Locate a suitable plugin to store the secret.
    key_spec = secret_store.KeySpec(alg=spec.get('algorithm'),
                                    bit_length=spec.get('bit_length'),
                                    passphrase=spec.get('passphrase'))

    plugin_manager = secret_store.get_manager()
    generate_plugin = plugin_manager.get_plugin_generate(
        key_spec, project_id=project_model.id)

    # Create secret models to eventually save metadata to.
    private_secret_model = models.Secret(spec)
    private_secret_model['secret_type'] = secret_store.SecretType.PRIVATE
    public_secret_model = models.Secret(spec)
    public_secret_model['secret_type'] = secret_store.SecretType.PUBLIC
    passphrase_secret_model = (models.Secret(spec)
                               if spec.get('passphrase') else None)
    if passphrase_secret_model:
        passphrase_type = secret_store.SecretType.PASSPHRASE
        passphrase_secret_model['secret_type'] = passphrase_type

    asymmetric_meta_dto = _generate_asymmetric_key(
        generate_plugin,
        key_spec,
        private_secret_model,
        public_secret_model,
        passphrase_secret_model,
        project_model,
        content_type
    )

    _save_secret_in_repo(private_secret_model, project_model)
    _save_secret_metadata_in_repo(private_secret_model,
                                  asymmetric_meta_dto.private_key_meta,
                                  generate_plugin,
                                  content_type)

    _save_secret_in_repo(public_secret_model, project_model)
    _save_secret_metadata_in_repo(public_secret_model,
                                  asymmetric_meta_dto.public_key_meta,
                                  generate_plugin,
                                  content_type)

    if passphrase_secret_model:
        _save_secret_in_repo(passphrase_secret_model, project_model)
        _save_secret_metadata_in_repo(passphrase_secret_model,
                                      asymmetric_meta_dto.passphrase_meta,
                                      generate_plugin,
                                      content_type)

    container_model = _create_container_for_asymmetric_secret(spec,
                                                              project_model)
    _save_asymmetric_secret_in_repo(
        container_model, private_secret_model, public_secret_model,
        passphrase_secret_model)

    return container_model


def delete_secret(secret_model, project_id):
    """Remove a secret from secure backend."""

    secret_metadata = _get_secret_meta(secret_model)

    # We should only try to delete a secret using the plugin interface if
    # there's the metadata available. This addresses bug/1377330.
    if secret_metadata:
        # Locate a suitable plugin to delete the secret from.
        plugin_manager = secret_store.get_manager()
        delete_plugin = plugin_manager.get_plugin_retrieve_delete(
            secret_metadata.get('plugin_name'))

        # Delete the secret from plugin storage.
        delete_plugin.delete_secret(secret_metadata)

    # Delete the secret from data model.
    secret_repo = repos.get_secret_repository()
    secret_repo.delete_entity_by_id(entity_id=secret_model.id,
                                    external_project_id=project_id)


def _store_secret_using_plugin(store_plugin, secret_dto, secret_model,
                               project_model):
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


def _generate_asymmetric_key(generate_plugin, key_spec, private_secret_model,
                             public_secret_model, passphrase_secret_model,
                             project_model, content_type):
    if isinstance(generate_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            private_secret_model=private_secret_model,
            public_secret_model=public_secret_model,
            passphrase_secret_model=passphrase_secret_model,
            content_type=content_type)
        asymmetric_meta_dto = generate_plugin.generate_asymmetric_key(
            key_spec, context)
    else:
        asymmetric_meta_dto = generate_plugin.generate_asymmetric_key(key_spec)
    return asymmetric_meta_dto


def _get_secret(retrieve_plugin, secret_metadata, secret_model, project_model):
    if isinstance(retrieve_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            secret_model=secret_model)
        secret_dto = retrieve_plugin.get_secret(secret_model.secret_type,
                                                secret_metadata,
                                                context)
    else:
        secret_dto = retrieve_plugin.get_secret(secret_model.secret_type,
                                                secret_metadata)
    return secret_dto


def _get_secret_meta(secret_model):
    if secret_model:
        secret_meta_repo = repos.get_secret_meta_repository()
        return secret_meta_repo.get_metadata_for_secret(secret_model.id)
    else:
        return {}


def _save_secret_metadata_in_repo(secret_model, secret_metadata,
                                  store_plugin, content_type):
    """Add secret metadata to a secret."""

    if not secret_metadata:
        secret_metadata = {}

    secret_metadata['plugin_name'] = utils.generate_fullname_for(store_plugin)
    secret_metadata['content_type'] = content_type

    secret_meta_repo = repos.get_secret_meta_repository()
    secret_meta_repo.save(secret_metadata, secret_model)


def _save_secret_in_repo(secret_model, project_model):
    """Save a Secret entity."""

    secret_repo = repos.get_secret_repository()
    # Create Secret entities in data store.
    if not secret_model.id:
        secret_model.project_id = project_model.id
        secret_repo.create_from(secret_model)
    else:
        secret_repo.save(secret_model)


def _secret_already_has_stored_data(secret_model):
    if not secret_model:
        return False
    return secret_model.encrypted_data or secret_model.secret_store_metadata


def _create_container_for_asymmetric_secret(spec, project_model):
    container_model = models.Container()
    container_model.name = spec.get('name')
    container_model.type = spec.get('algorithm', '').lower()
    container_model.status = models.States.ACTIVE
    container_model.project_id = project_model.id
    container_model.creator_id = spec.get('creator_id')
    return container_model


def _save_asymmetric_secret_in_repo(container_model, private_secret_model,
                                    public_secret_model,
                                    passphrase_secret_model):
    container_repo = repos.get_container_repository()
    container_repo.create_from(container_model)

    # create container_secret for private_key
    _create_container_secret_association('private_key',
                                         private_secret_model,
                                         container_model)

    # create container_secret for public_key
    _create_container_secret_association('public_key',
                                         public_secret_model,
                                         container_model)

    if passphrase_secret_model:
        # create container_secret for passphrase
        _create_container_secret_association('private_key_passphrase',
                                             passphrase_secret_model,
                                             container_model)


def _create_container_secret_association(assoc_name, secret_model,
                                         container_model):
    container_secret = models.ContainerSecret()
    container_secret.name = assoc_name
    container_secret.container_id = container_model.id
    container_secret.secret_id = secret_model.id

    container_secret_repo = repos.get_container_secret_repository()
    container_secret_repo.create_from(container_secret)
