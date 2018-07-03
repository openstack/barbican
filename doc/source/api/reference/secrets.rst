***********************
Secrets API - Reference
***********************

GET /v1/secrets
###############
Lists a project's secrets.

The list of secrets can be filtered by the parameters passed in via the URL.

The actual secret payload data will not be listed here. Clients must instead
make a separate call to retrieve the secret payload data for each individual
secret.

.. _secret_parameters:

Parameters
**********

+-------------+---------+-----------------------------------------------------------------+
| Name        | Type    | Description                                                     |
+=============+=========+=================================================================+
| offset      | integer | The starting index within the total list of the secrets that    |
|             |         | you would like to retrieve.                                     |
+-------------+---------+-----------------------------------------------------------------+
| limit       | integer | The maximum number of records to return (up to 100). The        |
|             |         | default limit is 10.                                            |
+-------------+---------+-----------------------------------------------------------------+
| name        | string  | Selects all secrets with name similar to this value.            |
+-------------+---------+-----------------------------------------------------------------+
| alg         | string  | Selects all secrets with algorithm similar to this value.       |
+-------------+---------+-----------------------------------------------------------------+
| mode        | string  | Selects all secrets with mode similar to this value.            |
+-------------+---------+-----------------------------------------------------------------+
| bits        | integer | Selects all secrets with bit_length equal to this value.        |
+-------------+---------+-----------------------------------------------------------------+
| secret_type | string  | Selects all secrets with secret_type equal to this value.       |
+-------------+---------+-----------------------------------------------------------------+
| acl_only    | boolean | Selects all secrets with an ACL that contains the user.         |
|             |         | Project scope is ignored.                                       |
+-------------+---------+-----------------------------------------------------------------+
| created     | string  | Date filter to select all secrets with `created` matching the   |
|             |         | specified criteria.  See Date Filters below for more detail.    |
+-------------+---------+-----------------------------------------------------------------+
| updated     | string  | Date filter to select all secrets with `updated` matching the   |
|             |         | specified criteria. See Date Filters below for more detail.     |
+-------------+---------+-----------------------------------------------------------------+
| expiration  | string  | Date filter to select all secrets with `expiration` matching    |
|             |         | the specified criteria. See Date Filters below for more detail. |
+-------------+---------+-----------------------------------------------------------------+
| sort        | string  | Determines the sorted order of the returned list.  See Sorting  |
|             |         | below for more detail.                                          |
+-------------+---------+-----------------------------------------------------------------+

Date Filters:
*************

The values for the ``created``, ``updated``, and ``expiration`` parameters are
comma-separated lists of time stamps in ISO 8601 format.  The time stamps can
be prefixed with any of these comparison operators: ``gt:`` (greater-than),
``gte:`` (greater-than-or-equal), ``lt:`` (less-than), ``lte:`` (less-than-or-equal).

For example, to get a list of secrets that will expire in January of 2020:

.. code-block:: ini

    GET /v1/secrets?expiration=gte:2020-01-01T00:00:00,lt:2020-02-01T00:00:00

Sorting:
********

The value of the ``sort`` parameter is a comma-separated list of sort keys.
Supported sort keys include ``created``, ``expiration``, ``mode``, ``name``,
``secret_type``, ``status``, and ``updated``.

Each sort key may also include a direction.  Supported directions
are ``:asc`` for ascending and ``:desc`` for descending.  The service will
use ``:asc`` for every key that does not include a direction.

For example, to sort the list from most recently created to oldest:

.. code-block:: ini

    GET /v1/secrets?sort=created:desc


Request:
********

.. code-block:: javascript

   GET /v1/secrets?offset=1&limit=2&sort=created
   Headers:
       Accept: application/json
       X-Auth-Token: {keystone_token}
       (or X-Project-Id: {project id})

Response:
*********

.. code-block:: javascript

    {
        "next": "http://{barbican_host}:9311/v1/secrets?limit=2&offset=3",
        "previous": "http://{barbican_host}:9311/v1/secrets?limit=2&offset=0",
        "secrets": [
            {
                "algorithm": null,
                "bit_length": null,
                "content_types": {
                    "default": "application/octet-stream"
                },
                "created": "2015-04-07T03:37:19.805835",
                "creator_id": "3a7e3d2421384f56a8fb6cf082a8efab",
                "expiration": null,
                "mode": null,
                "name": "opaque octet-stream base64",
                "secret_ref": "http://{barbican_host}:9311/v1/secrets/{uuid}",
                "secret_type": "opaque",
                "status": "ACTIVE",
                "updated": "2015-04-07T03:37:19.808337"
            },
            {
                "algorithm": null,
                "bit_length": null,
                "content_types": {
                    "default": "application/octet-stream"
                },
                "created": "2015-04-07T03:41:02.184159",
                "creator_id": "3a7e3d2421384f56a8fb6cf082a8efab",
                "expiration": null,
                "mode": null,
                "name": "opaque random octet-stream base64",
                "secret_ref": "http://{barbican_host}:9311/v1/secrets/{uuid}",
                "secret_type": "opaque",
                "status": "ACTIVE",
                "updated": "2015-04-07T03:41:02.187823"
            }
        ],
        "total": 5
    }

.. _secret_response_attributes:

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| secrets  | list    | Contains a list of secrets.  The attributes in the secret    |
|          |         | objects are the same as for an individual secret.            |
+----------+---------+--------------------------------------------------------------+
| total    | integer | The total number of secrets available to the user.           |
+----------+---------+--------------------------------------------------------------+
| next     | string  | A HATEOAS URL to retrieve the next set of secrets based on   |
|          |         | the offset and limit parameters. This attribute is only      |
|          |         | available when the total number of secrets is greater than   |
|          |         | offset and limit parameter combined.                         |
+----------+---------+--------------------------------------------------------------+
| previous | string  | A HATEOAS URL to retrieve the previous set of secrets based  |
|          |         | on the offset and limit parameters. This attribute is only   |
|          |         | available when the request offset is greater than 0.         |
+----------+---------+--------------------------------------------------------------+


.. _secret_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+


.. _post_secrets:

POST /v1/secrets
################
Creates a Secret entity.  If the ``payload`` attribute is not included in the
request, then only the metadata for the secret is created, and a
subsequent PUT request is required.

Attributes
**********

+----------------------------+---------+-----------------------------------------------------+------------+
| Attribute Name             | Type    | Description                                         | Default    |
+============================+=========+=====================================================+============+
| name                       | string  | (optional) The name of the secret set by the        | None       |
|                            |         | user.                                               |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| expiration                 | string  | (optional) This is a UTC timestamp in ISO           | None       |
|                            |         | 8601 format ``YYYY-MM-DDTHH:MM:SSZ``.  If           |            |
|                            |         | set, the secret will not be available after         |            |
|                            |         | this time.                                          |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| algorithm                  | string  | (optional) Metadata provided by a user or           | None       |
|                            |         | system for informational purposes.                  |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| bit_length                 | integer | (optional) Metadata provided by a user or           | None       |
|                            |         | system for informational purposes. Value            |            |
|                            |         | must be greater than zero.                          |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| mode                       | string  | (optional) Metadata provided by a user or           | None       |
|                            |         | system for informational purposes.                  |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| payload                    | string  | (optional) The secret's data to be stored.          | None       |
|                            |         | ``payload_content_type`` must also be               |            |
|                            |         | supplied if payload is included.                    |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| payload_content_type       | string  | (optional) (required if payload is included)        | None       |
|                            |         | The media type for the content of the               |            |
|                            |         | payload.  For more information see                  |            |
|                            |         | :doc:`Secret Types <../reference/secret_types>`     |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| payload_content_encoding   | string  | (optional) (required if payload is encoded)         | None       |
|                            |         | The encoding used for the payload to be able        |            |
|                            |         | to include it in the JSON request.                  |            |
|                            |         | Currently only ``base64`` is supported.             |            |
+----------------------------+---------+-----------------------------------------------------+------------+
| secret_type                | string  | (optional) Used to indicate the type of             | ``opaque`` |
|                            |         | secret being stored.  For more information          |            |
|                            |         | see :doc:`Secret Types <../reference/secret_types>` |            |
+----------------------------+---------+-----------------------------------------------------+------------+

Request:
********

.. code-block:: javascript

    POST /v1/secrets
    Headers:
        Content-Type: application/json
        X-Auth-Token: <token>

    Content:
    {
        "name": "AES key",
        "expiration": "2015-12-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload": "YmVlcg==",
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64"
    }

Response:
*********

.. code-block:: javascript

    201 Created

    {
        "secret_ref": "https://{barbican_host}/v1/secrets/{secret_uuid}"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successfully created a Secret                                               |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden.  The user has been authenticated, but is not authorized to       |
|      | create a secret. This can be based on the user's role or the                |
|      | project's quota.                                                            |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported media-type                                                      |
+------+-----------------------------------------------------------------------------+


GET /v1/secrets/{uuid}
######################
Retrieves a secret's metadata.

Request:
*****************

.. code-block:: javascript

    GET /v1/secrets/{uuid}
    Headers:
        Accept: application/json
        X-Auth-Token: {token}
        (or X-Project-Id: {project_id})

Response:
******************

.. code-block:: javascript

    200 OK

    {
        "status": "ACTIVE",
        "created": "2015-03-23T20:46:51.650515",
        "updated": "2015-03-23T20:46:51.654116",
        "expiration": "2015-12-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "name": "AES key",
        "secret_ref": "https://{barbican_host}/v1/secrets/{secret_uuid}",
        "secret_type": "opaque",
        "content_types": {
            "default": "application/octet-stream"
        }
    }

Payload Request:
****************

.. warning::

   DEPRECATION WARNING: Previous releases of the API allowed the payload to be
   retrieved from this same endpoint by changing the Accept header to be one
   of the values listed in the ``content_types`` attribute of the Secret
   metadata.  This was found to be problematic in some situations, so new
   applications should make use of the :ref:`/v1/secrets/{uuid}/payload <secret_payload>`
   endpoint instead.

.. code-block:: javascript

    GET /v1/secrets/{uuid}
    Headers:
        Accept: application/octet-stream
        X-Auth-Token: <token>


Payload Response:
*****************

.. code-block:: javascript

    200 OK

    beer


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+
| 406  | Not Acceptable                                                              |
+------+-----------------------------------------------------------------------------+

.. _put_secrets:

PUT /v1/secrets/{uuid}
######################

Add the payload to an existing metadata-only secret, such as one made by
sending a POST /v1/secrets request that does not include the ``payload``
attribute.

.. note::

    This action can only be done for a secret that doesn't have a payload.

Headers
*******

+------------------+-----------------------------------------------------------+------------+
| Name             | Description                                               | Default    |
+==================+===========================================================+============+
| Content-Type     | Corresponds with the payload_content_type                 | text/plain |
|                  | attribute of a normal secret creation request.            |            |
+------------------+-----------------------------------------------------------+------------+
| Content-Encoding | (optional) Corresponds with the payload_content_encoding  | None       |
|                  | attribute of a normal secret creation request.            |            |
+------------------+-----------------------------------------------------------+------------+

Request:
********

.. code-block:: javascript

    PUT /v1/secrets/{uuid}
    Headers:
        X-Auth-Token: <token>
        Content-Type: application/octet-stream
        Content-Encoding: base64

    Content:
    YmxhaA==

Response:
*********

.. code-block:: javascript

    204 No Content

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+

.. _delete_secrets:

DELETE /v1/secrets/{uuid}
#########################

Delete a secret by uuid

Request:
********

.. code-block:: javascript

    DELETE /v1/secrets/{uuid}
    Headers:
        X-Auth-Token: <token>

Response:
*********

.. code-block:: javascript

    204 No Content

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+

.. _secret_payload:

GET /v1/secrets/{uuid}/payload
##############################
Retrieve a secret's payload

Accept Header Options:
**********************

When making a request for a secret's payload, you must set the accept header
to one of the values listed in the ``content_types`` attribute of a secret's
metadata.


Request:
********

.. code-block:: javascript

    GET /v1/secrets/{uuid}/payload
    Headers:
        Accept: text/plain
        X-Auth-Token: <token>

Response:
*********

.. code-block:: javascript

    200 OK

    beer

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+
| 406  | Not Acceptable                                                              |
+------+-----------------------------------------------------------------------------+
