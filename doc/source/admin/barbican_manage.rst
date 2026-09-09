===================================
Barbican Service Management Utility
===================================

Description
===========
``barbican-manage`` is a utility that is used to control the barbican key
manager service database and Hardware Secure Module (HSM) plugin device. Use
cases include migrating the secret database or generating a Master Key
Encryption Key (MKEK) in the HSM. This command set should only be executed by
a user with admin privileges.

Options
=======

The standard pattern for executing a barbican-manage command is:

``barbican-manage <category> <command> [<args>]``

Running ``barbican-manage`` without arguments shows a list of available command
categories. Supported categories include *db*, *hsm*, *secret*, and
*simple_crypto*.

Running with a category argument shows a list of commands in that category:

* ``barbican-manage db --help``
* ``barbican-manage hsm --help``
* ``barbican-manage secret --help``
* ``barbican-manage --version`` shows the version number of barbican service.

The following sections describe the available categories and arguments for
barbican-manage.

Barbican Database
~~~~~~~~~~~~~~~~~

.. Warning::
    Before executing **barbican-manage db** commands, make sure you are
    familiar with `Database Migration`_ first.

``barbican-manage db revision [--db-url] [--message] [--autogenerate]``

    Create a new database version file.

``barbican-manage db upgrade [--db-url] [--version]``

    Upgrade to a future version database.

``barbican-manage db history [--db-url] [--verbose]``

    Show database changeset history.

``barbican-manage db current [--db-url] [--verbose]``

    Show current revision of database.

``barbican-manage db clean [--db-url] [--verbose] [--min-days] [--clean-unassociated-projects] [--soft-delete-expired-secrets] [--log-file]``

    Clean up soft deletions in the database. More documentation can be
    found here: :doc:`Database Cleaning <database_cleaning>`

``barbican-manage db sync_secret_stores [--db-url] [--verbose] [--log-file]``

    Synchronize the secret_store database table with the configuration
    in barbican.conf.  This is useful when multiple secret stores are
    enabled and new secret stores have been enabled.

Barbican PKCS11/HSM
~~~~~~~~~~~~~~~~~~~

``barbican-manage hsm gen_mkek [--library-path] [--passphrase] [--slot-id] [--label] [--length]``

    Create a new Master key encryption key in HSM.
    This MKEK will be used to encrypt all project key encryption keys.
    Its label must be unique.

``barbican-manage hsm gen_hmac [--library-path] [--passphrase] [--slot-id] [--label] [--length]``

    Create a new Master HMAC key in HSM.
    This HMAC key will be used to generate an authentication tag of encrypted
    project key encryption keys. Its label must be unique.

``barbican-manage hsm rewrap_pkek [--dry-run]``

    Rewrap project key encryption keys after rotating to new MKEK and/or HMAC
    key(s) in HSM. The new MKEK and HMAC key should have already been generated
    using the above commands. The user will have to configure new MKEK and HMAC
    key labels in /etc/barbican/barbican.conf and restart barbican server before
    executing this command.

    This rewraps project KEKs on the **same** PKCS#11 HSM after MKEK or HMAC
    rotation. To move secret payloads onto a different secret store, use
    ``barbican-manage secret migrate`` (see
    :doc:`/cli/barbican-manage-secret-migrate`).

Barbican secret stores
~~~~~~~~~~~~~~~~~~~~~~

``barbican-manage secret migrate [--dest-store-id] [--source-store-id] [--project-id] [--secret-id] [--secret-ids-file] [--yes] [--dry-run] [--error-file]``

    Migrate secret payloads onto another configured secret store without
    changing secret UUIDs. Discovers candidates from the Barbican database
    and calls ``plugin.resources.rewrap_secret`` in-process. Bulk
    migrates prompt for confirmation unless ``--yes`` or ``--dry-run``
    is set. Full flags, examples, and exit codes:
    :doc:`/cli/barbican-manage-secret-migrate`. Overview:
    :doc:`/admin/secret_store_migrate`.

.. _Database Migration: https://docs.openstack.org/barbican/latest/contributor/database_migrations.html
