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
