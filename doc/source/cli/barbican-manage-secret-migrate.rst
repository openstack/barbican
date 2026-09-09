=================================
barbican-manage secret migrate
=================================

Synopsis
========

::

  barbican-manage secret migrate --dest-store-id <store-uuid>
                                 (--project-id <keystone-project-uuid>
                                  [--source-store-id <store-uuid>] |
                                  --source-store-id <store-uuid> |
                                  --secret-id <secret-uuid-or-href> ... |
                                  --secret-ids-file <path>)
                                 [--yes] [--dry-run]
                                 [--error-file <path>]

Description
===========

``barbican-manage secret migrate`` is an **operator** subcommand that
runs on a Barbican API node. It discovers secrets from the Barbican
database, then moves each payload onto another configured secret store
by calling ``plugin.resources.rewrap_secret`` in-process.
It does not make HTTP calls to Barbican or Keystone.

It never fetches or prints payloads. The secret UUID, ACLs, consumers,
and container membership are unchanged. Secrets that are already on
the destination store are skipped. Soft-deleted and expired secrets
are never migrated.

Bulk migrates (``--project-id`` or ``--source-store-id``) prompt for
confirmation after discovery unless ``--yes`` or ``--dry-run`` is set.
Non-interactive bulk runs without ``--yes`` exit with status ``2``.

This is not a replacement for
:program:`barbican-manage hsm rewrap_pkek`, which rewraps project KEKs
after rotating keys on the same PKCS#11 HSM.

Project members migrating a single secret should use
``openstack secret migrate`` instead. See
:doc:`/admin/secret_store_migrate`.

Prerequisites
=============

* Run the command where ``barbican.conf`` is available (typically
  inside the barbican-api container). The command reads the database
  connection and plugin configuration from that file, including HSM
  and KMIP settings used by ``rewrap_secret``.
* ``enable_multiple_secret_stores = True`` with at least two stores.
  See :doc:`/configuration/plugin_backends`.
* The destination store UUID must exist in the ``secret_stores`` table
  (``GET /v1/secret-stores``).

Modes
=====

Migrate one Keystone project
----------------------------

Every non-deleted, non-expired secret with a payload in that project::

  $ barbican-manage secret migrate \
      --dest-store-id 93869b0f-60eb-4830-adb9-e2f7154a080b \
      --project-id 2a0f1c3e-9b44-4c6a-8d1e-0b7a9c4d5e6f

The command prints how many secrets will be migrated and asks for
confirmation. Pass ``--yes`` to skip the prompt (for example in
scripts). Optional ``--source-store-id`` limits the set to secrets
whose **current** backend is that store.

Drain one backend (all projects)
--------------------------------

Every payload secret whose computed current store is the source UUID::

  $ barbican-manage secret migrate \
      --source-store-id 11111111-1111-1111-1111-111111111111 \
      --dest-store-id 93869b0f-60eb-4830-adb9-e2f7154a080b

Preview first with ``--dry-run`` (no plugin rewrap, no confirmation
prompt).

Explicit retry list
-------------------

Owning project is looked up in the database. No confirmation prompt::

  $ barbican-manage secret migrate \
      --dest-store-id 93869b0f-60eb-4830-adb9-e2f7154a080b \
      --secret-ids-file /tmp/secret-ids.txt

Options
=======

``--dest-store-id <uuid>``
  Destination secret store UUID. Required.

``--source-store-id <uuid>``
  Only secrets whose current backend is this store. Required unless
  ``--project-id`` or an explicit secret id list is given. Cannot be
  the same UUID as ``--dest-store-id``.

``--project-id <uuid>``
  Keystone project id (Barbican ``projects.external_id``). Migrates
  secrets in that project only.

``--secret-id <uuid-or-href>``
  Secret UUID or secret href. Repeatable. Cannot be combined with
  ``--project-id`` or ``--source-store-id``.

``--secret-ids-file <path>``
  File of secret UUIDs or hrefs, one per line. Blank lines and lines
  that start with ``#`` are ignored.

``--yes``
  Skip the confirmation prompt for a bulk migrate (``--project-id``
  or ``--source-store-id``). Not needed for an explicit secret id
  list or for ``--dry-run``.

``--dry-run``
  Print the secrets that would be migrated. Do not call
  ``rewrap_secret``. Also lists secrets already on the destination as
  ``SKIP``. Discover problems (for example an explicit id that cannot
  be resolved) are still printed and written to ``--error-file``, but
  the command exits ``0`` because dry-run is advisory. No confirmation
  prompt.

``--error-file <path>``
  JSONL file written when any secret fails (live migrate or dry-run).
  Defaults to ``barbican-manage-secret-migrate-errors.jsonl`` in the
  current directory.

Return codes
============

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Return code
     - Description
   * - 0
     - Live migrate: every requested secret succeeded (or there was
       nothing to migrate). Dry-run: always ``0`` after discovery
       completes, even when some ids are reported as ``FAIL``.
   * - 1
     - Live migrate only: at least one secret failed. Remaining
       secrets were still attempted. Failure records were written to
       the error file.
   * - 2
     - Setup failed (bad arguments, missing store/project, Barbican
       runtime, or database error), or a bulk migrate was declined /
       could not be confirmed. No rewrap calls were made.

Error file
==========

Each failed secret is one JSON object per line::

  {"error": "...", "name": "",
   "project_id": "...", "secret_id": "...",
   "source_store_id": "...", "target_store": "..."}

Typical errors include metadata-only secrets (no payload), missing
plugin configuration, and destination ``store_secret`` failures.

The ``error`` field is a short message. Payloads are never included.

See also
========

* :doc:`/admin/secret_store_migrate`
* :doc:`/admin/barbican_manage`
* :doc:`/api/microversion_history`
* :doc:`/api/reference/store_backends`
