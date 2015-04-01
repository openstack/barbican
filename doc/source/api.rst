=================================
Application Programming Interface
=================================

THESE DOCS ARE DEPRECATED AS OF APR 2015
########################################


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

Secrets Resource Moved to :doc:`Secrets Reference <api/reference/secrets>`

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

Containers Resource Moved to :doc:`Containers Reference <api/reference/containers>`

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
