==========================================
Migrating secrets between secret stores
==========================================

Barbican can run with more than one secret store plugin (for example
software crypto, PKCS#11, and KMIP). Changing the global default or a
project preferred store only affects **new** secrets. Existing payloads
stay on the store that created them until they are migrated.

Use the migrate API to move a payload onto another configured store
**without** changing the secret UUID. Consuming services that already
hold the UUID do not need to be updated.

This is not the same as PKCS#11 MKEK rotation.
:command:`barbican-manage hsm rewrap_pkek` rewraps project KEKs after
you rotate keys on the **same** HSM. It does not move a secret to a
different backend.

When to migrate
===============

Migrate when you need the same secret UUID on a different backend, for
example:

* Moving project secrets from a central HSM onto a project-dedicated
  HSM or KMIP server.
* Moving a subset of secrets from software crypto onto PKCS#11.
* Draining one backend so it can be removed.

Recreate (store a new secret and retarget consumers) when you cannot
enable multiple backends, or when the secret has no payload
(metadata-only secrets cannot be migrated).

Prerequisites
=============

* ``enable_multiple_secret_stores = True`` with at least two stores.
  See :doc:`/configuration/plugin_backends`.
* A token that passes policy ``secret:migrate_secretstore``
  (default: project ``admin`` to any store, or project ``member``
  only to the project preferred store).
* The destination store listed by ``GET /v1/secret-stores``.
  See :doc:`/api/reference/store_backends`.

Which tool to use
=================

OSC (one secret, tenant or operator)
------------------------------------

Project members and project administrators can migrate a single
secret::

  $ openstack secret migrate \
      <secret-uuid> \
      --secret-store <store-uuid>

Members may migrate only onto the **project preferred** store (or the
global default when the project has no preferred store). Migrating to
any other backend returns HTTP **403**. Project **admins** may target
any configured store.

This requires python-barbicanclient with microversion 1.3 support.

Operator command (one project, or one backend)
----------------------------------------------

``barbican-manage secret migrate`` runs on the Barbican API node. It
reads ``barbican.conf``, queries the database for the secrets to
move, then calls ``plugin.resources.rewrap_secret``
in-process (the same code path as the HTTP migrate API, without
Keystone or HTTP).

Use it to:

* migrate every payload secret in a specified Keystone project
* migrate every payload secret currently on a specified backend
  (all projects)

It continues after per-secret failures and never prints payloads.
CLI flags, examples, and exit codes are in
:doc:`/cli/barbican-manage-secret-migrate`.

API
---

Microversion 1.3::

  PUT /v1/secrets/{secret-id}/secret-store/{secret-store-id}
  OpenStack-API-Version: key-manager 1.3

The request body is empty. Success is ``204 No Content``. See
:doc:`/api/microversion_history`.

The migrate API does not persist a ``secret_store_id`` on the secret
row. After a successful migrate, the payload is stored only on the
destination plugin. Secret metadata GET (microversion 1.3) always
returns computed ``secret_store_id`` / ``secret_store_ref`` (``null``
when multiple backends are disabled or the secret has no payload).
A live payload that cannot be mapped to exactly one catalogue store
is an error (HTTP 500).

Failure handling
================

* A secret that is already on the destination store succeeds as a
  no-op on the API. The operator command skips those secrets and does
  not rewrap them.
* Concurrent migrates of the same secret UUID are serialized with a
  ``SELECT ... FOR UPDATE`` row lock. The second request re-checks
  after the lock and no-ops when the first already moved the payload.
* Metadata-only secrets return ``400``. The operator command records
  them as failures and continues.
* Decrypt or destination ``store_secret`` failures leave the secret on
  the source store (no database rewrite has started yet).
* If a migrate fails after the destination plugin accepted the payload,
  the API rolls back the Barbican database change and deletes the new
  plugin object. The secret remains on the source store.
* ``barbican-manage secret migrate`` continues with remaining secrets.
  It writes one JSON object per failure to
  ``barbican-manage-secret-migrate-errors.jsonl`` (or ``--error-file``)
  and exits ``1`` if any secret failed on a live run. ``--dry-run``
  still records discover failures in that file but exits ``0``.

See also
========

* :doc:`/cli/barbican-manage-secret-migrate`
* :doc:`/admin/barbican_manage`
* :doc:`/configuration/plugin_backends`
* :doc:`/api/reference/store_backends`

