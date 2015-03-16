=================================
Application Programming Interface
=================================

This wiki page details the API for the latest Barbican release. In particular:

* `Endpoints & Versioning`_ - Brief discussion about Barbican's approach to
  service URIs.
* `Secrets Resource`_ - Details storing, retrieving and deleting secrets.
* `Orders Resource`_ - Details the ordering facilities for Barbican, used
  to generate secrets asynchronously.
* `Containers Resource`_ - Details storing, retrieving and deleting
  containers.
* `Consumers Resource`_ - Details adding, removing and listing consumers
  associated with container instances.
* `Examples`_ - Provides specific examples utilizing the secrets and
  orders API.

Endpoints & Versioning
======================

The barbican service is assumed to be hosted on an SSL enabled, geographically
labelled endpoint. An example for a valid URI might look like the following:

    https://dfw.secrets.api.rackspacecloud.com

Versioning will be achieved through a URI constant element, as shown in the
example below:

    https://dfw.secrets.api.rackspacecloud.com/v1/

Regarding Role Based Access Control (RBAC) of Resources
=======================================================

Resource access in Barbican is subject to RBAC constraints, as detailed in
`this link`_.
RBAC failures will result in a 403 Forbidden response.

.. _`this link`: https://github.com/cloudkeep/barbican/wiki/Role-Based-Access-Control

Secrets Resource
================

The secrets resource is the heart of the Barbican service. It provides access
to the secret / keying material stored in the system.

The secret scheme represents the actual secret or key that will be presented to
the application. Secrets can be of several formats, but additional
functionality may be available for known types of symmetric or asymmetric keys.
The schema for storing a secret differs from the retrieval schema is shown
next.

Storing Secrets
---------------

Secrets can be stored in two ways: Via POST including a payload ('one step'
secret storage), or with a POST without a payload followed by a PUT ('two step'
secret storage).

Note that the POST calls create secret _metadata_. If the payload is provided
with the POST call, then it is encrypted and stored, and then linked with this
metadata. Otherwise, a follow-on PUT call provides this payload. Hence clients
must provide the secret information payload to store via these operations. This
should not be confused with the secret 'generation' process via the `orders`
resource below, whereby Barbican generates the secret information payload on
clients' behalf.

POST
~~~~

Below is an example of a `secret` POST request that includes a payload.

.. code-block:: javascript

    POST v1/secrets

    Header: content-type=application/json
            X-Project-Id: {project_id}

    {
      "name": "AES key",
      "expiration": "2014-02-28T19:14:44.180394",
      "algorithm": "aes",
      "bit_length": 256,
      "mode": "cbc",
      "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
      "payload_content_type": "application/octet-stream",
      "payload_content_encoding": "base64",
      "secret_type": "opaque"
    }

Where:

* **name** - (optional) Human readable name for the secret. If a name is not
  supplied, the UUID will be displayed for this field on subsequent GET calls
  (see below).
* **expiration** - (optional) The expiration date for the secret in ISO-8601
  format. Once the secret has expired, it will no longer be returned by the
  API or agent. If this field is not supplied, then the secret has no
  expiration date.
* **algorithm** - (optional) The algorithm type used to generate the secret.
  _Barbican does not attempt to validate the information provided here, as it
  is client/application specific._
* **bit_length** - (optional) The bit-length of the secret. Must be an integer
  one or greater. *Barbican does not attempt to validate the information
  provided here, as it is client/application specific.*
* **mode** - (optional) The type/mode of the algorithm associated with the
  secret information. _Barbican does not attempt to validate the information
  provided here, as it is client/application specific._
* **payload** - (optional) The secret's unencrypted plain text. If provided,
  this field's value must be non-empty, and you must also provide the
  `payload_content_type`. This field can be omitted allowing for the secret
  information to be provided via a subsequent PUT call (see below)._
* **payload_content_type** - (optional) The type/format the secret data is
  provided in. Required if `payload` is specified.  Supported values are:

  * _"text/plain"_ - Used to store plain text secrets.

    * Other options are _"text/plain; charset=utf-8"_. If charset is
      omitted, utf-8 will be assumed.
    * Note that some types are normalized before being stored as secret
      meta-data, such as converting "text/plain; charset=utf-8" to
      "text/plain". *Hence retrieved meta-data may not exactly match what
      was specified in the POST or PUT calls*.
    * payload_content_encoding must **not** be specified when
      payload_content_type is _"text/plain"_

  * _"application/octet-stream"_ - Used to store binary secrets from a base64
    encoded payload.  If this value is used, you must also include the
    content encoding.

* **payload_content_encoding** - (optional) The _encoding_ format used to
  provide the payload data. Barbican might translate and store the secret data
  into another format. _Required if `payload_content_type` is
  "application/octet-stream"._  Supported values are:

  * _"base64"_ - Used to specify base64 encoded payloads.

* **secret_type** - (optional) Used to indicate the type of secret being
  stored. If no value is given, `opaque` is used as the default, which is used
  to signal Barbican to just store the information without worrying about
  format or encoding. Options for this value are `symmetric`, `public`,
  `private`, `passphrase`, `certificate`, `opaque`.

If the `payload` is not provided, only the secret metadata will be retrievable
from Barbican and any attempt to retrieve decrypted data for that secret will
fail. Deferring the secret information to a PUT request is useful for secrets
that are in binary format and are not suitable for base64 encoding.

If the Content-Type in the HTTP header is not set to "application/json" then
the POST call will fail with an HTTP 415 error.

If the POST call succeeds, a URI to the new secret will be provided such as per
the example below:

.. code-block:: javascript

    {
        "secret_ref": "http://localhost:9311/v1/secrets/a8957047-16c6-4b05-ac57-8621edd0e9ee"
    }

PUT
~~~

To provide secret information after the secret's metadata is add, clients would
send a PUT request to the secret URI. Note that **a PUT request can only be
performed once after a POST call that does not include a payload**.  Also note
that no other attributes of a secret can be modified via PUT after it is
POST-ed (i.e. secrets are immutable).

The PUT request must include the appropriate Content-Type and Content-Encoding
definitions. (see Examples below for more information.)

Retrieving Secrets
------------------

Secrets are comprised of metadata about the secret (algorithm, bit-length,
etc.) and encrypted payload data associated with the secret. Hence the API
supports retrieving either a secret's metadata or its decrypted data.

GET - Individual Secret - Metadata Only
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

GET requests for a `secret` with an `Accept` header set to `application/json`
will return a response such as the one below. Only metadata about the secret is
returned, rather than the decrypted secret information itself. This allows for
a more rapid response for large secrets, or large lists of secrets, as well as
accommodating multi-part secrets such as SSL certificates, which may have both
a public and private key portions that could be individually retrieved.

An example GET call for an individual secret is below.

.. code-block:: javascript

    GET v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718
    Headers: X-Project-Id: {project_id}

    {
      "status": "ACTIVE",
      "secret_type": "symmetric",
      "updated": "2013-06-28T15:23:33.092660",
      "name": "AES key",
      "algorithm": "AES",
      "mode": "cbc",
      "bit_length": 256,
      "content_types": {
        "default": "application/octet-stream"
      },
      "expiration": "2013-05-08T16:21:38.134160",
      "secret_ref": "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718",
    }

Where:

* **secret_type** - See POST example above.
* **name** - Human readable name for the secret. If a name was not provided
  during the POST call above, then its UUID is returned.
* **algorithm** - See POST example above.
* **mode** - See POST example above.
* **bit_length** - See POST example above.
* **content_types** - Available content mime types for the format of the
  decrypted secret. For example, SSL certificates may have both 'public' (for
  public key) and 'private' (for private key) types available.

  * *This value is only shown if a secret has encrypted data associated with
    it.*
  * Note that some types are normalized, such as converting "text/plain;
    charset=utf-8" to "text/plain". *Hence retrieved meta-data may not
    exactly match what was specified in the POST or PUT calls*.

* **expiration** - UTC time when the secret will expire.  Attempting to
  retrieve a secret after the expiration date will result in an error.
* **secret_ref** - Self URI to the secret.

GET - List of Secrets Per Project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Performing a GET on the secrets resource with no UUID retrieves a batch of the
most recent secrets (metadata only) per the requesting project, as per the
example response below. The `limit` and `offset` parameters are used to control
pagination of the secrets list, as described after this example.

.. code-block:: javascript

    GET http://localhost:9311/v1/secrets?limit=3&offset=2
    Headers: X-Project-Id: {project_id}

    {
      "secrets": [
        {
          "status": "ACTIVE",
          "secret_type": "symmetric",
          "updated": "2013-06-28T15:23:30.668641",
          "mode": "cbc",
          "name": "Main Encryption Key",
          "algorithm": "AES",
          "created": "2013-06-28T15:23:30.668619",
          "secret_ref": "http://localhost:9311/v1/secrets/e171bb2d-f14f-433e-84f0-3dfcac7a7311",
          "expiration": "2014-06-28T15:23:30.668619",
          "bit_length": 256,
          "content_types": {
            "default": "application/octet-stream"
          }
        },
        {
          "status": "ACTIVE",
          "secret_type": "symmetric",
          "updated": "2013-06-28T15:23:32.210474",
          "mode": "cbc",
          "name": "Backup Key",
          "algorithm": "AES",
          "created": "2013-06-28T15:23:32.210467",
          "secret_ref": "http://localhost:9311/v1/secrets/6dba7827-c232-4a2b-8f3d-f523ca3a3f99",
          "expiration": null,
          "bit_length": 256,
          "content_types": {
            "default": "application/octet-stream"
          }
        },
        {
          "status": "ACTIVE",
          "secret_type": "passphrase"
          "updated": "2013-06-28T15:23:33.092660",
          "mode": null,
          "name": "PostgreSQL admin password",
          "algorithm": null,
          "created": "2013-06-28T15:23:33.092635",
          "secret_ref": "http://localhost:9311/v1/secrets/6dfa448d-c35a-4158-abaf-e4c249efb580",
          "expiration": null,
          "bit_length": null,
          "content_types": {
            "default": "text/plain"
          }
        }
      ],
      "next": "http://localhost:9311/v1/secrets?limit=3&offset=5",
      "previous": "http://localhost:9311/v1/secrets?limit=3&offset=0"
    }

The retrieved list of secrets is ordered by oldest to newest `created` date.
The URL parameters (`?limit=3&offset=2` in this example) provide a way to
window or page the retrieved list, with the `offset` representing how many
records to skip before retrieving the list, and the `limit` representing the
maximum number of records retrieved (up to `100`). If the parameters are not
provided, then up to `10` records are retrieved.

To access any records before the retrieved list, the 'previous' link is
provided. The 'next' link can be used to retrieve records after the current
list.

GET - Decrypted Secret Data
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To retrieve the decrypted secret information, perform a GET with the `Accept`
header set to one of the `content_types` specified in the GET metadata call.
Note that even if a binary secret is provided in the `base64` format, it is
converted to binary by Barbican prior to encryption and storage. _Thereafter
the secret will only be decrypted and returned as raw binary._ See examples
below for more info.

Secrets Summary
---------------

> https://.../v1/secrets

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Allows a user to list all secrets in a project. _Note: the actual |
|        | secret payload data will not be listed here. Clients must instead |
|        | make a separate call to get the secret details to view the        |
|        | secret._                                                          |
+--------+-------------------------------------------------------------------+
| POST   | Allows a user to create a new secret. This call expects the user  |
|        | to provide a secret. To have the API generate a secret, see the   |
|        | `orders` API below. Returns 201 if the secret has been created.   |
+--------+-------------------------------------------------------------------+

> https://.../v1/secrets/{secret_uuid}/

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Gets the information for the specified secret. For the            |
|        | `application/json` accept type, only metadata about the secret is |
|        | returned. If one of the 'content_types' accept types is specified |
|        | instead, that portion of the secret will be decrypted and         |
|        | returned.                                                         |
+--------+-------------------------------------------------------------------+
| PUT    | Allows the user to upload secret data for a specified secret _(if |
|        | the secret does not already have data associated with it)_.       |
|        | Returns 200 on a successful request.                              |
+--------+-------------------------------------------------------------------+
| DELETE | Deletes the secret.                                               |
+--------+-------------------------------------------------------------------+

Error Responses
~~~~~~~~~~~~~~~

+------------------------+-------+-------------------------------------------+
| Action                 | Error | Notes                                     |
|                        | Code  |                                           |
+========================+=======+===========================================+
| POST secret with       | 400   | Can include schema violations such as     |
| invalid data           |       | mime-type not specified.                  |
+------------------------+-------+-------------------------------------------+
| POST secret with       | 400   | The 'payload' JSON attribute was          |
| 'payload' empty        |       | provided, but no value was assigned to    |
|                        |       | it.                                       |
+------------------------+-------+-------------------------------------------+
| POST secret with       | 413   | Current size limit is 10,000 bytes        |
| 'payload' too          |       |                                           |
| large                  |       |                                           |
+------------------------+-------+-------------------------------------------+
| POST secret with       | 400   | Caused when no crypto plugin supports the |
| 'payload_content_type' |       | payload_content_type requested            |
| not supported          |       |                                           |
+------------------------+-------+-------------------------------------------+
| POST secret with       | 415   | Caused when the API doesn't support the   |
| 'Content-Type' header  |       | specified Content-Type header             |
| not supported          |       |                                           |
+------------------------+-------+-------------------------------------------+
| GET secret that        | 404   | The supplied UUID doesn't match a secret  |
| doesn't exist          |       | in the data store                         |
+------------------------+-------+-------------------------------------------+
| GET secret with        | 406   | The secret data cannot be retrieved in    |
| unsupported Accept     |       | the requested Accept header mime-type     |
+------------------------+-------+-------------------------------------------+
| GET secret (non-JSON)  | 404   | The secret metadata has been created, but |
| with no associated     |       | the encrypted data for it has not yet been|
| encrypted data         |       | supplied, hence cannot be retrieved via a |
|                        |       | non 'application/json' mime type          |
+------------------------+-------+-------------------------------------------+
| PUT secret that        | 404   | The supplied UUID doesn't match a secret  |
| doesn't exist          |       | in the data store for the given project   |
+------------------------+-------+-------------------------------------------+
| PUT secret with        | 415   | Caused when no crypto plugin supports the |
| unsupported            |       | payload_content_type requested in the     |
| Content-Type           |       | Content-Type                              |
+------------------------+-------+-------------------------------------------+
| PUT secret that        | 409   | Secret already has encrypted data         |
| already has encrypted  |       | associated with it                        |
| data                   |       |                                           |
+------------------------+-------+-------------------------------------------+
| PUT secret with empty  | 400   | No value was provided in the payload      |
| 'payload' data         |       |                                           |
+------------------------+-------+-------------------------------------------+
| PUT secret with too    | 413   | Current size limit is 10,000 bytes for    |
| large 'payload' data   |       | uploaded secret data                      |
+------------------------+-------+-------------------------------------------+
| DELETE secret that     | 404   | The supplied UUID doesn't match a secret  |
| doesn't exist          |       | in the data store                         |
+------------------------+-------+-------------------------------------------+


Orders Resource
===============

The ordering resource allows for the generation of secret material by Barbican.
The ordering object encapsulates the workflow and history for the creation of a
secret. This interface is implemented as an asynchronous process since the time
to generate a secret can vary depending on the type of secret.

POST
----

An example of an `orders` POST request is below.

.. code-block:: javascript

    POST v1/orders

    Header: content-type=application/json
            X-Project-Id: {project_id}
    {
      "type": "key",
      "meta": {
        "name": "secretname",
        "algorithm": "AES",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream"
      }
    }

Where the elements of the `meta` element match those of the `secret` POST
request above, but without the `payload` attributes. _Note however that unlike
with the `secrets` resource, the `algorithm`, `bit_length` and `mode`
attributes are validated, to ensure that a secret can be generated per these
specifications._ The `type` parameter selects the secret to generate: `key`
generates a symmetric key; `asymmetric` generates a public/private PKI key pair
(in a Container object); certificate` generates an SSL certificate (not
currently operational).

If the Content-Type in the HTTP header is not set to "application/json" then
the POST call will fail with an HTTP 415 error.

PUT
---

Currently nothing can be edited in an order.

GET - Individual Order
----------------------

GET requests for an `order` will return a response such as in the example
below.

.. code-block:: javascript

    GET v1/orders/{order_id}
    Headers: X-Project-Id: {project_id}

    {
      "type": "key",
      "meta": {
        "name": "secretname",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream"
      },
      "order_ref": "http://localhost:8080/v1/orders/f9b633d8-fda5-4be8-b42c-5b2c9280289e",
      "secret_ref": "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718",
      "status": "ERROR",
      "error_status_code": "400 Bad Request",
      "error_reason": "Secret creation issue seen - content-encoding of 'bogus' not supported."
    }

Where:

* **meta** - Secret parameters provided in the original order request. _Note
  that this is not the same as retrieving a Secret resource per the `secrets`
  resource, so elements such as a secret's `content_types` will not be
  displayed. To see such details, perform a GET on the `secret_ref`._
* **type** - Secret type in the original order request.
* **order_ref** - URI to this order.
* **status** - Status of the order, one of PENDING, ACTIVE or ERROR. Clients
  should poll the order for a status change to ACTIVE (in which case
  `secret_ref` has the secret details) or ERROR (in which case `error_reason`
  has the error reason, and 'error_status_code' has an HTTP-style status code).
* **secret_ref** - URI to the secret *once it is generated*. This field is not
  available unless the status is ACTIVE.
* **error_status_code** - (optional) HTTP-style status code of the root cause
  error condition, only if status is ERROR.
* **error_reason** - (optional) Details of the root cause error condition, only
  if status is ERROR.

GET - List of Orders Per Project
--------------------------------

Performing a GET on the orders resource with no UUID retrieves a batch of the
most recent orders per the requesting project, as per the example response
below. The `limit` and `offset` parameters function similar to the GET secrets
list detailed above.

.. code-block:: javascript

    GET http://localhost:9311/v1/orders?limit=3&offset=2
    Headers: X-Project-Id: {project_id}

    {
      "orders": [
        {
          "status": "ACTIVE",
          "secret_ref": "http://localhost:9311/v1/secrets/bf2b33d5-5347-4afb-9009-b4597f415b7f",
          "updated": "2013-06-28T18:29:37.058718",
          "created": "2013-06-28T18:29:36.001750",
          "type": "key",
          "meta": {
            "name": "secretname",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload_content_type": "application/octet-stream"
          },
          "order_ref": "http://localhost:9311/v1/orders/3100078a-6ab1-4c3f-ab9f-295938c91733"
        },
        {
          "status": "ACTIVE",
          "secret_ref": "http://localhost:9311/v1/secrets/fa71b143-f10e-4f7a-aa82-cc292dc33eb5",
          "updated": "2013-06-28T18:29:37.058718",
          "created": "2013-06-28T18:29:36.001750",
          "type": "key",
          "meta": {
            "name": "secretname",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload_content_type": "application/octet-stream"
          },
          "order_ref": "http://localhost:9311/v1/orders/30b3758a-7b8e-4f2c-b9f0-f590c6f8cc6d"
        }
      ]
    }

The retrieved list of orders is ordered by oldest to newest `created` date.

Orders Summary
--------------

> https://.../v1/orders/

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Returns a list of all orders for a customer.                      |
+--------+-------------------------------------------------------------------+
| POST   | Starts the process of creating a secret. This call will return    |
|        | immediately with a 202 OK and a link to the detail order object   |
|        | (see below).                                                      |
+--------+-------------------------------------------------------------------+

> https://.../v1/orders/{order_uuid}

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Returns the detailed order data including a link to the secret    |
|        | generated as a result of the order (if available).                |
+--------+-------------------------------------------------------------------+
| PUT    | **Not yet supported**. Allows the editing of an order where       |
|        | allowed.                                                          |
+--------+-------------------------------------------------------------------+
| DELETE | Cancels an order.                                                 |
+--------+-------------------------------------------------------------------+

Error Responses
~~~~~~~~~~~~~~~

+------------------------+-------+-------------------------------------------+
| Action                 | Error | Notes                                     |
|                        | Code  |                                           |
+========================+=======+===========================================+
| POST order with        | 400   | Can include schema violations such as the |
| invalid data           |       | secret's mime-type not specified          |
+------------------------+-------+-------------------------------------------+
| POST order with        | 415   | Caused when the API doesn't support the   |
| 'Content-Type' header  |       | specified Content-Type header             |
| not supported          |       |                                           |
+------------------------+-------+-------------------------------------------+
| POST secret with       | 400   | Caused when no crypto plugin supports the |
| 'payload_content_type' |       | payload_content_type requested            |
| not supported          |       |                                           |
+------------------------+-------+-------------------------------------------+
| GET order that doesn't | 404   | The supplied UUID doesn't match a order   |
| exist                  |       | in the data store                         |
+------------------------+-------+-------------------------------------------+
| DELETE order that      | 404   | The supplied UUID doesn't match a order   |
| doesn't exist          |       | in the data store                         |
+------------------------+-------+-------------------------------------------+


Containers Resource
===================

Containers store references to secrets. There are currently three types of
containers ("generic", "rsa", and "certificate").

Generic type containers can hold multiple references to secrets, each reference
defining a relation name to the secret. RSA type containers can hold 3 secret
references, named 'public_key', 'private_key', and 'private_key_passphrase'.
Certificate type containers must hold a 'certificate', but may optionally hold
any or all of 'private_key', 'private_key_passphrase', and 'intermediates'.

POST
----

Below is an example of a `container` POST request.

.. code-block:: javascript

    POST v1/containers

    Header: content-type=application/json

    {
      "name": "container name",
      "type": "rsa",
      "secret_refs": [
        {
           "name": "private_key",
           "secret_ref":"http://localhost:9311/v1/secrets/05a47308-d045-43d6-bfe3-1dbcd0c3a97b"
        },
        {
           "name": "public_key",
           "secret_ref":"http://localhost:9311/v1/secrets/8b9ea25d-2324-4ef3-891f-2a821ad88ed1"
        },
        {
           "name": "private_key_passphrase",
           "secret_ref":"http://localhost:9311/v1/secrets/c39c04dd-e423-457e-8993-063d8a0a187c"
        }
      ]
    }


Where:

* **name** - (optional) Human readable name for the container. If a name is not
  supplied, the UUID will be displayed for this field on subsequent GET calls
  (see below).
* **type** - The type of the container. Type can be "generic", "rsa", or
  "certificate". The "generic" type containers can store multiple arbitrary
  named references to secrets; "rsa" type can store 3 references, one each
  named "public_key", "private_key" and "private_key_passphrase"; "certificate"
  type must hold a "certificate", but may optionally hold any or all of
  "private_key", "private_key_passphrase", and "intermediates".
* **secret_refs** - (optional) Array of secret references.

If the POST call succeeds, a URI to the new container will be provided such as
per the example below:

.. code-block:: javascript

    {
        "container_ref": "http://localhost:9311/v1/containers/a8957047-16c6-4b05-ac57-8621edd0e9ee"
    }

If the Content-Type in the HTTP header is not set to "application/json" then
the POST call will fail with an HTTP 415 error.

PUT
---

Currently nothing can be edited in a container resource.

GET - Individual Container
--------------------------

GET requests for a container will return a response such as in the example
below

.. code-block:: javascript

    GET v1/containers/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718

    {
       "name":"rsa container",
       "secret_refs":[
          {
             "secret_ref":"http://localhost:9311/v1/secrets/059805d5-b400-47da-abc5-cae7286d3ede",
             "name":"private_key_passphrase"
          },
          {
             "secret_ref":"http://localhost:9311/v1/secrets/28704f0f-3273-40d4-bc40-4de2691135ea",
             "name":"private_key"
          },
          {
             "secret_ref":"http://localhost:9311/v1/secrets/29d89344-10ad-4f92-8aa2-adebaf7556ee",
             "name":"public_key"
          }
       ],
       "container_ref":"http://localhost:9311/v1/containers/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718",
       "type":"rsa"
    }

Where:

* **name** - Human readable name for the container. If a name was not provided
  during the POST call above, then its UUID is returned.
* **type** - Type of the container.
* **container_ref** - Self URI to the container.
* **secret_refs** - Array of named secret references.

GET - List of Containers Per Project
------------------------------------

Performing a GET on the containers resource with no UUID retrieves a batch of
the most recent containers per the requesting project, as per the example
response below. The `limit` and `offset` parameters function similar to the GET
secrets list detailed above.

.. code-block:: javascript

    GET http://localhost:9311/v1/containers?limit=3&offset=2
    Headers: X-Project-Id: {project_id}

    {
       "total":42,
       "containers":[
          {
             "status":"ACTIVE",
             "updated":"2014-02-11T18:05:58.909411",
             "name":"generic container_updated",
             "secret_refs":[
                {
                   "secret_id":"123",
                   "name":"private_key"
                },
                {
                   "secret_id":"321",
                   "name":"public_key"
                },
                {
                   "secret_id":"456",
                   "name":"private_key_passphrase"
                }
             ],
             "created":"2014-02-11T18:05:58.909403",
             "container_ref":"http://localhost:9311/v1/containers/d4e06015-4f6e-4626-ac3d-4ece6621f96d",
             "type":"rsa"
          },
          {
             "status":"ACTIVE",
             "updated":"2014-02-11T18:08:58.160557",
             "name":"generic container_updated",
             "secret_refs":[
                {
                   "secret_id":"321",
                   "name":"public_key"
                },
                {
                   "secret_id":"456",
                   "name":"private_key_passphrase"
                }
             ],
             "created":"2014-02-11T18:08:58.160551",
             "container_ref":"http://localhost:9311/v1/containers/bb24fa61-0b5f-4d40-8990-846e95cd7b12",
             "type":"rsa"
          },
          {
             "status":"ACTIVE",
             "updated":"2014-02-11T18:25:58.198072",
             "name":"generic container_updated",
             "secret_refs":[
                {
                   "secret_id":"1df433d6-c2d4-480d-90fb-0bfd9c5da3dd",
                   "name":"private_key"
                },
                {
                   "secret_id":"321",
                   "name":"public_key"
                },
                {
                   "secret_id":"456",
                   "name":"private_key_passphrase"
                }
             ],
             "created":"2014-02-11T18:25:58.198063",
             "container_ref":"http://localhost:9311/v1/containers/38f58696-5013-4bd6-ab2b-fbea41dc957a",
             "type":"rsa"
          },
          {
             "status":"ACTIVE",
             "updated":"2014-02-11T18:44:06.296957",
             "name":"generic container_updated",
             "secret_refs":[
                {
                   "secret_id":"1df433d6-c2d4-480d-90fb-0bfd9c5da3dd",
                   "name":"private_key"
                },
                {
                   "secret_id":"321",
                   "name":"public_key"
                },
                {
                   "secret_id":"456",
                   "name":"private_key_passphrase"
                }
             ],
             "created":"2014-02-11T18:44:06.296947",
             "container_ref":"http://localhost:9311/v1/containers/a8d1adfd-0d36-4eb0-8762-99787eb4a7ff",
             "type":"rsa"
          }
       ],
       "next":"http://localhost:9311/v1/containers?limit=10&offset=10"
    }

The retrieved list of containers is ordered by oldest to newest `created` date.
The URL parameters (`?limit=3&offset=2` in this example) provide a way to
window or page the retrieved list, with the `offset` representing how many
records to skip before retrieving the list, and the `limit` representing the
maximum number of records retrieved (up to `100`). If the parameters are not
provided, then up to `10` records are retrieved.

To access any records before the retrieved list, the 'previous' link is
provided. The 'next' link can be used to retrieve records after the current
list.

Containers Summary
------------------

> https://.../v1/containers

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Allows a user to list all containers in a project._               |
+--------+-------------------------------------------------------------------+
| POST   | Allows a user to create a new container. Returns 201 if the       |
|        | container has been created.                                       |
+--------+-------------------------------------------------------------------+

> https://.../v1/containers/{container_uuid}/

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Gets the information for the specified container.                 |
+--------+-------------------------------------------------------------------+
| PUT    | Currently not supported.                                          |
+--------+-------------------------------------------------------------------+
| DELETE | Deletes the container.                                            |
+--------+-------------------------------------------------------------------+

Error Responses
~~~~~~~~~~~~~~~

+------------------------+-------+-------------------------------------------+
| Action                 | Error | Notes                                     |
|                        | Code  |                                           |
+========================+=======+===========================================+
| POST container with    | 400   | Can include schema violations such as     |
| invalid data           |       | container type not specified              |
+------------------------+-------+-------------------------------------------+
| GET container that     | 404   | The supplied UUID doesn't match a         |
| doesn't exist          |       | container in the data store               |
+------------------------+-------+-------------------------------------------+
| DELETE container that  | 404   | The supplied UUID doesn't match a secret  |
| doesn't exist          |       | in the data store                         |
+------------------------+-------+-------------------------------------------+


Consumers Resource
==================

The consumers resource allows clients to register as interested in specific
container instances (as created per the previous section). Clients can then
query containers for the consumers that registered interest in them. Client
workflows could use this list (for example) to warn of attempts to remove
containers that have registered consumers. Note that Barbican allows containers
to be deleted even if there are registered consumers for them.

POST
----

An example of an `consumers` POST request is below.

.. code-block:: javascript

    POST v1/containers/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718/consumers

    Header: content-type=application/json
            X-Project-Id: {project_id}
    {
        "name": "foo-service",
        "URL": "https://www.fooservice.com/widgets/1234"
    }

Where the `name` is typically the name of the remote service registering as a
consumer for this container instance, and 'URL' is typically a URL to a
resource in the remote service that utilizes the container's secrets somehow,
such as a load balancer that has a container's SSL certificate installed onto
it.

Note that subsequent POSTs to the same container instance with the same `name`
attribute will replace the previous URL registered for that `name`.

GET - List of Consumers Per Container Instance
----------------------------------------------

**Note: This feature seems to be broken currently, by not displaying the
navigation links per the example below.**

Performing a GET on a specific container resource returns a list of consumers
that registered with it. The `limit` and `offset` parameters function similar
to the GET secrets list detailed above.

.. code-block:: javascript

    GET http://localhost:9311/v1/containers/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718/consumers?limit=3&offset=2
    Headers: X-Project-Id: {project_id}

    {
      "consumers": [
        {
            "name": "foo-service",
            "URL": "https://www.fooservice.com/widgets/1234"
        },
        {
            "name": "barService",
            "URL": "https://www.barservice.com/mythings/5678"
        }
      ],
       "next":"http://localhost:9311/v1/containers/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718/consumers?limit=10&offset=10"
    }

The retrieved list of consumers is ordered by oldest to newest `created` date.

Consumers Summary
-----------------

> https://.../v1/containers/<container-UUID>/consumers

+--------+-------------------------------------------------------------------+
| Method | Description                                                       |
+========+===================================================================+
| GET    | Returns a list of all consumers registered for a container.       |
+--------+-------------------------------------------------------------------+
| POST   | Registers/adds consumer information to a container.               |
+--------+-------------------------------------------------------------------+
| DELETE | Removes a registered consumer by specifying its `name` and `URL`  |
|        | in the JSON payload.                                              |
+--------+-------------------------------------------------------------------+

Examples
========

The following are example combinations, inspired by `this page`_.

.. _`this page`: http://stackoverflow.com/questions/11946920/http-content-negotiation-compression-use-base64-with-accept-encoding-content-en

The tables in this section are focused on the content-types and
content-encodings of the various REST verb flows, even though each flow might
have a different way to specify these values (either via http header settings
or JSON request field). The reason for this approach is that while each flow
has a different means to specify the mime-type and encoding, the values set for
them must still be consistent with valid mime-type or encoding selections.

One-Step UTF-8/ASCII Secret Create/Retrieve
-------------------------------------------

+--------------------+---------------------------------------+-----------------------------+---------------------------------+
| Action             | content-type                          | content-encoding            | Result                          |
+====================+=======================================+=============================+=================================+
| POST secrets       | `payload_content_type` = `text/plain` | `payload_content_encoding`  | Supplied `payload` is encrypted |
|                    |                                       | Not required/ignored        |                                 |
+--------------------+---------------------------------------+-----------------------------+---------------------------------+
| GET secrets (meta) | `Accept: application/json`            | Not required/ignored        | JSON metadata, with             |
|                    |                                       |                             | `Content-Types` set to          |
|                    |                                       |                             | `'default':'text/plain'`        |
+--------------------+---------------------------------------+-----------------------------+---------------------------------+
| GET secrets        | `Accept: text/plain`                  | Not required/ignored        | Previous `payload` is decrypted |
|                    |                                       |                             | and returned                    |
+--------------------+---------------------------------------+-----------------------------+---------------------------------+


One-Step Binary Secret Create/Retrieve
--------------------------------------

+--------------------+---------------------------------------+---------------------------------------+----------------------------------------+
| Action             | content-type                          | content-encoding                      | Result                                 |
+====================+=======================================+=======================================+========================================+
| POST secrets       | `payload_content_type` =              | `payload_content_encoding` = `base64` | Supplied `payload` is converted from   |
|                    | `application/octet-stream`            |                                       | base64 to binary, then encrypted.      |
+--------------------+---------------------------------------+---------------------------------------+----------------------------------------+
| GET secrets (meta) | `Accept: application/json`            | Not required/ignored                  | JSON metadata, with `Content-Types`    |
|                    |                                       |                                       | set to                                 |
|                    |                                       |                                       | `'default':'application/octet-stream'` |
+--------------------+---------------------------------------+---------------------------------------+----------------------------------------+
| GET secrets        | `Accept: application/octet-stream`    | Not specified                         | Previous `payload` is decrypted and    |
| (decrypted)        |                                       |                                       | returned as raw binary, *even if the   |
|                    |                                       |                                       | POST provided the data in `base64`*.   |
+--------------------+---------------------------------------+---------------------------------------+----------------------------------------+

Two-Step Binary Secret Create/Retrieve
--------------------------------------

+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+
| Action             | content-type                             | content-encoding                      | Result                                |
+====================+==========================================+=======================================+=======================================+
| POST secrets       | `payload_content_type`                   | `payload_content_encoding` Not        | Only metadata is created. If the      |
|                    |  Not required/ignored                    | required/ignored                      | `payload_content_type` or             |
|                    |                                          |                                       | `payload_content_encoding` fields     |
|                    |                                          |                                       | were provided, they are not used or   |
|                    |                                          |                                       | saved with the metadata. The PUT      |
|                    |                                          |                                       | request (next) will determine the     |
|                    |                                          |                                       | secret's content type                 |
+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+
| PUT secrets        | `Content-Type: application/octet-stream` | `Content-Encoding: base64`            | Supplied request body is *converted   |
| (option #1 - as    |                                          |                                       | from base64 to binary*, then          |
| base64)            |                                          |                                       | encrypted                             |
+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+
| PUT secrets        | `Content-Type: application/octet-stream` | Not specified                         | Supplied request body is encrypted as |
| (option #2 - as    |                                          |                                       | is                                    |
| binary)            |                                          |                                       |                                       |
+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+
| GET secrets (meta) | `Accept: application/json`               | Not required/ignored                  | JSON metadata, with `Content-Types`   |
|                    |                                          |                                       | set to                                |
|                    |                                          |                                       | `'default':'application/octet-stream'`|
+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+
| GET secrets        | `Accept: application/octet-stream`       | Not specified                         | Previous request is decrypted and     |
| (decrypted)        |                                          |                                       | returned as raw binary, *even if the  |
|                    |                                          |                                       | PUT provided the data in `base64`*.   |
+--------------------+------------------------------------------+---------------------------------------+---------------------------------------+


Two-Step Plain-Text Secret Create/Retrieve
------------------------------------------

+--------------------+---------------------------------------+---------------------------------------+---------------------------------------+
| Action             | content-type                          | content-encoding                      | Result                                |
+====================+=======================================+=======================================+=======================================+
| POST secrets       | `payload_content_type` Not            | `payload_content_encoding` Not        | Only metadata is created. If the      |
|                    | required/ignored                      | required/ignored                      | `payload_content_type` or             |
|                    |                                       |                                       | `payload_content_encoding` fields     |
|                    |                                       |                                       | were provided, they are not used or   |
|                    |                                       |                                       | saved with the metadata. The PUT      |
|                    |                                       |                                       | request (next) will determine the     |
|                    |                                       |                                       | secret's content format               |
+--------------------+---------------------------------------+---------------------------------------+---------------------------------------+
| PUT secrets        | `Content-Type: text/plain`            | Not required/ignored                  | Supplied request body is encrypted as |
|                    |                                       |                                       | is                                    |
+--------------------+---------------------------------------+---------------------------------------+---------------------------------------+
| GET secrets (meta) | `Accept: application/json`            | Not required/ignored                  | JSON metadata, with `Content-Types`   |
|                    |                                       |                                       | set to `'default':'text/plain'`       |
+--------------------+---------------------------------------+---------------------------------------+---------------------------------------+
| GET secrets        | `Accept: text/plain`                  | Not specified                         | Previous request is decrypted and     |
| (decrypted)        |                                       |                                       | returned as utf-8 text                |
+--------------------+---------------------------------------+---------------------------------------+---------------------------------------+
