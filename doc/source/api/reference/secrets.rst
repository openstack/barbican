***********************
Secrets API - Reference
***********************

GET /v1/secrets
###############
Lists a project's secrets.

The list of secrets can be filtered by the parameters passed in via the URL.


The actual secret payload data will not be listed here. Clients must instead
make a separate call to get the secret details to view the secret.

.. _secret_parameters:

Parameters
**********

+----------+---------+----------------------------------------------------------------+
| Name     | Type    | Description                                                    |
+==========+=========+================================================================+
| offset   | integer | The starting index within the total list of the secrets that   |
|          |         | you would like to retrieve.                                    |
+----------+---------+----------------------------------------------------------------+
| limit    | integer | The maximum number of records to return (up to 100). The       |
|          |         | default limit is 10.                                           |
+----------+---------+----------------------------------------------------------------+
| name     | string  | Selects all secrets with name equal to this value.             |
+----------+---------+----------------------------------------------------------------+
| bits     | integer | Selects all secrets with bit_length equal to this value.       |
+----------+---------+----------------------------------------------------------------+
| alg      | string  | Selects all secrets with algorithm equal to this value.        |
+----------+---------+----------------------------------------------------------------+
| mode     | string  | Selects all secrets with mode equal to this value.             |
+----------+---------+----------------------------------------------------------------+
| acl_only | boolean | Selects all secrets with an ACL that contains the user.        |
|          |         | Project scope is ignored.                                      |
+----------+---------+----------------------------------------------------------------+

.. _secret_response_attributes:

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| secrets  | list    | Contains a list of dictionaries filled with secret metadata. |
+----------+---------+--------------------------------------------------------------+
| total    | integer | The total number of secrets available to the user.           |
+----------+---------+--------------------------------------------------------------+
| next     | string  | A HATEOS url to retrieve the next set of secrets based on    |
|          |         | the offset and limit parameters. This attribute is only      |
|          |         | available when the total number of secrets is greater than   |
|          |         | offset and limit parameter combined.                         |
+----------+---------+--------------------------------------------------------------+
| previous | string  | A HATEOS url to retrieve the previous set of secrets based   |
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
Creates a secret

Attributes
**********

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| name                       | string  | (optional) The name of the secret set by the | None       |
|                            |         | user.                                        |            |
+----------------------------+---------+----------------------------------------------+------------+
| expiration                 | string  | (optional) This is a timestamp in ISO 8601   | None       |
|                            |         | format ``YYYY-MM-DDTHH:MM:SSZ``. Once this   |            |
|                            |         | time has past, the secret will no longer be  |            |
|                            |         | available.                                   |            |
+----------------------------+---------+----------------------------------------------+------------+
| algorithm                  | string  | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes.           |            |
+----------------------------+---------+----------------------------------------------+------------+
| bit_length                 | integer | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes. Value     |            |
|                            |         | must be greater than zero.                   |            |
+----------------------------+---------+----------------------------------------------+------------+
| mode                       | string  | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes.           |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload                    | string  | (optional) The secret's data to be stored.   | None       |
|                            |         | ``payload_content_type`` must also be        |            |
|                            |         | supplied if payload is provided.             |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload_content_type       | string  | (optional) (required if payload is added)    | None       |
|                            |         | The type and format of the secret data. The  |            |
|                            |         | two supported types are ``text/plain`` and   |            |
|                            |         | ``application/octet-stream``.                |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload_content_encoding   | string  | (optional) The encoding used to format the   | None       |
|                            |         | payload provided. Currently only base64 is   |            |
|                            |         | supported. This is required if content type  |            |
|                            |         | provided has an encoding available.          |            |
+----------------------------+---------+----------------------------------------------+------------+
| secret_type                | string  | (optional) Used to indicate the type of      | ``opaque`` |
|                            |         | secret being stored. If no value is given,   |            |
|                            |         | ``opaque`` is used as the default, which is  |            |
|                            |         | used to signal Barbican to just store the    |            |
|                            |         | information without worrying about format or |            |
|                            |         | encoding.                                    |            |
+----------------------------+---------+----------------------------------------------+------------+

Request:
********

.. code-block:: javascript

    POST /v1/secrets
    Headers:
        Content-Type: application/json
        X-Project-Id: {project_id}

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

.. code-block:: none

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
|      | create a secret. This can be based on the the user's role or the            |
|      | project's quota.                                                            |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported media-type                                                      |
+------+-----------------------------------------------------------------------------+


GET /v1/secrets/{uuid}
######################
Retrieves a secret's metadata or payload via uuid.

The return type of content, metadata or payload, is controlled by the Accept
header.

Accept Header Options:
**********************

* application/json - Returns secret metadata
* application/octet-stream - Returns secret payload
* text/plain - Returns secret payload


Metadata Request:
*****************

.. code-block:: none

    GET /v1/secrets/{uuid}
    Headers:
        Accept: application/json
        X-Project-Id: {project_id}


Metadata Response:
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

.. code-block:: none

    GET /v1/secrets/{uuid}
    Headers:
        Accept: application/octet-stream
        X-Project-Id: {project_id}


Payload Response:
*****************

.. code-block:: none

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

Update a secret's payload by uuid

.. note::

    This action can only be done for a secret that doesn't have a payload already
    set.

Required Headers
****************

+------------------+---------------------------------------------------+------------+
| Name             | Description                                       | Default    |
+==================+===================================================+============+
| Content-Type     | Corresponds with the payload_content_type         | text/plain |
|                  | attribute of a normal secret creation request.    |            |
+------------------+---------------------------------------------------+------------+
| Content-Encoding | Corresponds with the payload_content_encoding     | None       |
|                  | attribute of a normal secret creation request.    |            |
+------------------+---------------------------------------------------+------------+

Request:
********

.. code-block:: none

    PUT /v1/secrets/{uuid}
    Headers:
        X-Project-Id: {project_id}
        Content-Type: application/octet-stream
        Content-Encoding: base64

    Content:
    YmxhaA==

Response:
*********

.. code-block:: none

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
****************

.. code-block:: none

    DELETE /v1/secrets/{uuid}
    Headers:
        X-Project-Id: {project_id}

Response:
****************

.. code-block:: none

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


GET /v1/secrets/{uuid}/payload
##############################
Retrieve a secret's payload

Accept Header Options:
**********************

* application/octet-stream - Returns secret payload
* text/plain - Returns secret payload

Request:
********

.. code-block:: none

    GET /v1/secrets/{uuid}/payload
    Headers:
        Accept: text/plain
        X-Project-Id: {project_id}

Response:
*********

.. code-block:: none

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
