REST API Version History
========================

This documents the changes made to the REST API with every
microversion change. The description for each version should be a
verbose one which has enough information to be suitable for use in
user documentation.

1.0
---

This is the initial version of the v1.0 API which supports
microversions.

A user can specify a header in the API request::

  OpenStack-API-Version: key-manager <version>

where ``<version>`` is any valid api version for this API.

If no version is specified then the API will behave as if a version
request of v1.0 was requested.

1.1 (Maximum in Wallaby)
---

Added Secret Consumers to Secrets.

When requesting Secrets (individual Secret or a list), the results contain an
additional ``consumers`` key, which contains references to Secret Consumers.

1.2 (Maximum in Hibiscus)
---

Deleting a secret that has consumers is rejected in the
API unless the ``force`` query parameter is sent.

1.3
---

Added ``PUT /v1/secrets/{secret-id}/secret-store/{secret-store-id}``
to migrate an existing secret payload onto a named secret store
without changing the secret UUID, ACLs, consumers, or container
membership.

The request body is empty. A successful migration returns
``204 No Content``. Multiple secret store backends must be enabled.
Default policy allows project admins to target any store, and
project members to migrate only to the project's preferred store.

The same microversion always adds computed ``secret_store_id`` /
``secret_store_ref`` fields on secret metadata GET and list
responses. Values are ``null`` when multiple backends are disabled
or the secret has no payload. A live payload that cannot be mapped
to exactly one catalogue store returns HTTP 500. These fields are
not persisted on the secret.

Secret-store catalogue responses
(``GET /v1/secret-stores``, get-by-id, preferred, and global-default)
also include ``secret_store_id`` alongside ``secret_store_ref``, so
clients can pass a UUID to migrate without parsing the href.

Operator usage is documented in :doc:`/admin/secret_store_migrate`.
