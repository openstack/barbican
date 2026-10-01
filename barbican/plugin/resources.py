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

import datetime

from oslo_utils import timeutils
from sqlalchemy import exc as sa_exc

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin.crypto import base as crypto_base
from barbican.plugin.crypto import manager as crypto_mgr
from barbican.plugin.interface import secret_store
from barbican.plugin import store_crypto
from barbican.plugin.util import translations as tr

LOG = utils.getLogger(__name__)
CONF = config.CONF


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


def get_preferred_secret_store_for_project(project_model):
    """Return the preferred SecretStores row for a project, or None."""
    if project_model is None:
        return None
    project_store_repo = repos.get_project_secret_store_repository()
    project_store = project_store_repo.get_secret_store_for_project(
        project_model.id, None, suppress_exception=True)
    if project_store is None:
        return None
    return project_store.secret_store


def get_effective_secret_store_id_for_project(project_model):
    """Return preferred or global-default store id for a project.

    Used by migrate policy so project members may only migrate onto the
    project's preferred store, or the global default when none is set.
    """
    if not utils.is_multiple_backends_enabled():
        return None
    preferred = get_preferred_secret_store_for_project(project_model)
    if preferred is not None:
        return preferred.id
    from barbican.plugin.util import multiple_backends
    default_store = multiple_backends.get_global_default_secret_store()
    return default_store.id if default_store else None


def resolve_secret_store_for_secret(secret_model):
    """Return the SecretStores row currently holding this secret, if any.

    Matches plugin identity the same way retrieve does, then maps that
    onto the unique ``secret_stores`` catalogue row.

    Returns None when multiple backends are disabled or the secret has
    no payload. Raises
    :class:`~barbican.common.exception.SecretStoreNotResolved`
    when the secret has a live payload but zero or multiple catalogue
    rows match (misconfiguration / removed backend).
    """
    if not utils.is_multiple_backends_enabled():
        return None
    if not _secret_has_payload(secret_model):
        return None
    stores_repo = repos.get_secret_stores_repository()
    matches = []
    for store in stores_repo.get_all():
        try:
            store_plugin, crypto_plugin = _resolve_plugins_for_store(store)
        except (secret_store.SecretStorePluginNotFound,
                crypto_base.CryptoPluginNotFound):
            LOG.debug('Skipping secret store %s while resolving current '
                      'store for secret %s', store.id, secret_model.id,
                      exc_info=True)
            continue
        if _secret_is_already_on_target(secret_model, store_plugin,
                                        crypto_plugin):
            matches.append(store)
    if len(matches) == 1:
        return matches[0]
    LOG.error(
        'Secret %s matched %s secret_stores rows while resolving '
        'computed secret_store_id', secret_model.id, len(matches))
    raise exception.SecretStoreNotResolved(secret_id=secret_model.id)


def rewrap_secret(secret_model, project_model, secret_store_model):
    """Move a secret payload onto a different secret store.

    Decrypts via the plugin currently associated with ``secret_model``,
    stores onto the target store, then always schedules asynchronous
    cleanup of the previous backend object (``store_crypto`` deletes
    are a no-op; external plugins such as KMIP destroy the old object).

    Takes a ``SELECT ... FOR UPDATE`` row lock on the secret so two
    concurrent migrates of the same UUID are serialized. The loser
    re-checks after the lock and no-ops when the winner already moved
    the payload onto the requested store.

    This is intentionally not ``store_secret()``, which refuses secrets
    that already have a payload.

    :param secret_model: Secret with an existing stored payload
    :param project_model: Project that owns the secret
    :param secret_store_model: Destination ``SecretStores`` row
    """
    secret_repo = repos.get_secret_repository()
    locked = secret_repo.get_secret_by_id(
        secret_model.id, for_update=True)

    if not _secret_has_payload(locked):
        raise exception.SecretPayloadNotFound()

    store_plugin, crypto_plugin = _resolve_plugins_for_store(
        secret_store_model)

    if _secret_is_already_on_target(locked, store_plugin,
                                    crypto_plugin):
        LOG.debug('Secret %s is already on the requested store',
                  locked.id)
        return

    current_meta = _get_secret_meta(locked)
    plugin_manager = secret_store.get_manager()
    retrieve_plugin = plugin_manager.get_plugin_retrieve_delete(
        current_meta.get('plugin_name'))
    secret_dto = _get_secret(
        retrieve_plugin, current_meta, locked, project_model)

    old_meta = current_meta
    old_datums = _get_encrypted_datums(locked)
    # Keep the type from retrieve, else the type already stored.
    # Default MIME is applied only in _save_secret_metadata_in_repo
    # when both are missing (None is not persisted).
    content_type = (
        secret_dto.content_type
        or old_meta.get('content_type')
    )

    new_meta = None
    rollback_meta = None
    try:
        new_meta = _store_secret_using_plugin(
            store_plugin, secret_dto, locked, project_model,
            crypto_plugin=crypto_plugin)
        rollback_meta = dict(new_meta) if new_meta else None
        # Drop the previous mapped collection first. Saving new keys
        # such as plugin_name into attribute_mapped_collection would
        # otherwise orphan-delete the live ORM rows, and a later
        # row.delete() raises InvalidRequestError.
        secret_meta_repo = repos.get_secret_meta_repository()
        if locked.id:
            secret_meta_repo.delete_for_secret(locked.id)
        if locked.secret_store_metadata:
            locked.secret_store_metadata.clear()
        _save_secret_metadata_in_repo(
            locked, new_meta, store_plugin, content_type)
        for datum in old_datums:
            if not getattr(datum, 'deleted', False):
                datum.delete()
    except (exception.BarbicanException, sa_exc.SQLAlchemyError):
        # Plugin or DB failure after a new backend object may exist.
        LOG.exception('Failed to migrate secret %s to store %s',
                      locked.id, secret_store_model.id)
        _schedule_rollback_cleanup(
            locked.id, rollback_meta, store_plugin)
        raise

    _schedule_plugin_cleanup(
        locked.id,
        old_meta,
        models.SecretStoreCleanupReason.SOURCE_AFTER_SUCCESS)


def _store_secret_using_plugin(store_plugin, secret_dto, secret_model,
                               project_model, crypto_plugin=None):
    if isinstance(store_plugin, store_crypto.StoreCryptoAdapterPlugin):
        context = store_crypto.StoreCryptoContext(
            project_model,
            secret_model=secret_model,
            crypto_plugin=crypto_plugin)
        secret_metadata = store_plugin.store_secret(secret_dto, context)
    else:
        secret_metadata = store_plugin.store_secret(secret_dto)
    return secret_metadata


def _resolve_plugins_for_store(secret_store_model):
    store_plugin = secret_store.get_manager().get_plugin_by_name(
        secret_store_model.store_plugin)
    crypto_plugin = None
    if secret_store_model.crypto_plugin:
        try:
            crypto_plugin = crypto_mgr.get_manager().get_plugin_by_name(
                secret_store_model.crypto_plugin)
        except crypto_base.CryptoPluginNotFound:
            raise crypto_base.CryptoPluginNotFound(
                u._('Crypto plugin "{name}" not found.').format(
                    name=secret_store_model.crypto_plugin))
    return store_plugin, crypto_plugin


def _get_encrypted_datums(secret_model):
    """Return non-deleted EncryptedDatum rows for a secret."""
    if not secret_model or not secret_model.encrypted_data:
        return []
    return [
        datum for datum in secret_model.encrypted_data
        if not getattr(datum, 'deleted', False)
    ]


def _secret_has_payload(secret_model):
    """Return True when the secret has a stored payload.

    Two local signals are checked:

    * Non-deleted ``EncryptedDatum`` rows — used by store_crypto, which
      keeps ciphertext in the Barbican database.
    * Non-empty **secret-store** (plugin) metadata from
      ``_get_secret_meta`` / ``SecretStoreMetadatum`` — used by external
      plugins (KMIP, Vault, …) that keep the payload on the backend and
      only persist plugin object keys locally (for example
      ``plugin_name`` and a remote object id). Those rows are written
      when the payload is stored, not for user-defined secret metadata.

    User-provided metadata (``SecretUserMetadatum``, the
    ``/v1/secrets/{id}/metadata`` API) is a different table and is not
    consulted here.
    """
    if _get_encrypted_datums(secret_model):
        return True
    return bool(_get_secret_meta(secret_model))


def _secret_is_already_on_target(secret_model, store_plugin, crypto_plugin):
    metadata = _get_secret_meta(secret_model)
    target_name = utils.generate_fullname_for(store_plugin)
    if metadata.get('plugin_name') != target_name:
        return False
    if crypto_plugin is None:
        return True
    if not isinstance(store_plugin,
                      store_crypto.StoreCryptoAdapterPlugin):
        return True
    datums = _get_encrypted_datums(secret_model)
    if not datums or not datums[0].kek_meta_project:
        return True
    return (datums[0].kek_meta_project.plugin_name ==
            utils.generate_fullname_for(crypto_plugin))


def _schedule_rollback_cleanup(secret_id, plugin_meta, store_plugin):
    """Roll back migrate DB changes, then persist dest-plugin cleanup.

    A destination plugin object may already exist. Rollback undoes the
    mapped metadata; the cleanup-task row is inserted in a new
    transaction for the retry scheduler to enqueue without a catch-all
    on the failed HTTP path.
    """
    repos.rollback()
    try:
        _schedule_plugin_cleanup(
            secret_id,
            plugin_meta,
            models.SecretStoreCleanupReason.DEST_AFTER_ROLLBACK,
            store_plugin=store_plugin)
    except (exception.BarbicanException, sa_exc.SQLAlchemyError):
        LOG.warning(
            'Failed to schedule dest plugin cleanup for secret %s',
            secret_id, exc_info=True)


def _schedule_plugin_cleanup(secret_id, plugin_meta, reason,
                             store_plugin=None):
    """Persist a cleanup-task row for the retry scheduler.

    Commits so the row is durable after migrate success or rollback.
    The retry scheduler enqueues barbican-worker; only plugin_name and
    plugin metadata are stored (never the secret payload).
    """
    if not plugin_meta:
        return
    meta = dict(plugin_meta)
    plugin_name = meta.get('plugin_name')
    if not plugin_name and store_plugin is not None:
        plugin_name = utils.generate_fullname_for(store_plugin)
        meta['plugin_name'] = plugin_name
    if not plugin_name:
        LOG.warning(
            'Cannot schedule plugin cleanup for secret %s: missing '
            'plugin_name', secret_id)
        return

    task = models.SecretStoreCleanupTask()
    task.secret_id = secret_id
    task.plugin_name = plugin_name
    task.plugin_meta = meta
    task.reason = reason
    task.retry_at = timeutils.utcnow()
    task.retry_count = 0

    cleanup_repo = repos.get_secret_store_cleanup_tasks_repository()
    cleanup_repo.create_from(task)
    repos.commit()


def process_secret_store_cleanup(task_id):
    """Delete a leftover secret-store plugin object for one cleanup task.

    Takes ``SELECT ... FOR UPDATE`` on the cleanup-task row so two
    workers cannot interleave soft-delete and reschedule on the same
    row (e.g. KMIP destroy succeeding on one worker and failing on the
    other).
    """
    cleanup_repo = repos.get_secret_store_cleanup_tasks_repository()
    task = cleanup_repo.get_for_update(
        entity_id=task_id, suppress_exception=True)
    if not task:
        return
    if task.status == models.States.ERROR:
        return

    try:
        plugin = secret_store.get_manager().get_plugin_retrieve_delete(
            task.plugin_name)
        plugin.delete_secret(task.plugin_meta)
    except secret_store.SecretNotFoundException:
        LOG.info(
            'Cleanup task %s: plugin object already gone', task_id)
    except exception.BarbicanException as err:
        _reschedule_cleanup_task(task, cleanup_repo, err)
        return

    task.delete()
    LOG.info('Completed secret-store plugin cleanup task %s', task_id)


def _reschedule_cleanup_task(task, cleanup_repo, err):
    max_retries = (
        CONF.retry_scheduler.secret_store_cleanup_max_retries)
    task.retry_count = (task.retry_count or 0) + 1
    task.last_error = str(err)[:models.ERROR_REASON_LENGTH]
    if task.retry_count >= max_retries:
        task.status = models.States.ERROR
        LOG.error(
            'Cleanup task %s exhausted retries: %s', task.id, err)
    else:
        task.retry_at = _next_cleanup_retry_at(task.retry_count)
        LOG.warning(
            'Cleanup task %s failed (attempt %s), retry at %s: %s',
            task.id, task.retry_count, task.retry_at, err)
    cleanup_repo.save(task)


def _next_cleanup_retry_at(retry_count):
    base = CONF.retry_scheduler.secret_store_cleanup_retry_msec
    cap = CONF.retry_scheduler.secret_store_cleanup_retry_max_msec
    delay_msec = min(base * (2 ** max(retry_count - 1, 0)), cap)
    return timeutils.utcnow() + datetime.timedelta(
        milliseconds=delay_msec)


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

    to_save = {
        key: value for key, value in (secret_metadata or {}).items()
        if value is not None
    }
    to_save['plugin_name'] = utils.generate_fullname_for(store_plugin)
    # SecretStoreMetadatumRepo.save skips None. Persist a MIME type so
    # GET payload can still resolve content_type later.
    to_save['content_type'] = (
        content_type or 'application/octet-stream'
    )

    secret_meta_repo = repos.get_secret_meta_repository()
    secret_meta_repo.save(to_save, secret_model)


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
