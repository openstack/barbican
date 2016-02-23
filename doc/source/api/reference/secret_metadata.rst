*******************************
Secret Metadata API - Reference
*******************************

.. _get_secret_metadata:

GET /v1/secrets/{uuid}/metadata
###############################
Lists a secret's user-defined metadata.

If a secret does not contain any user metadata, an empty list will be
returned.

Request:
********

.. code-block:: javascript

   GET /v1/secrets/{uuid}/metadata
   Headers:
       Accept: application/json
       X-Auth-Token: <token>

Response:
*********

.. code-block:: javascript

  {
    'metadata': {
      'description': 'contains the AES key',
      'geolocation': '12.3456, -98.7654'
      }
  }

.. _secret_metadata_response_attributes:

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| metadata | list    | Contains a list of the secret metadata's key/value pairs.    |
|          |         | The provided keys must be lowercase. If not they will be     |
|          |         | converted to lowercase.                                      |
+----------+---------+--------------------------------------------------------------+


.. _secret_metadata_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource.                                                                   |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | retrieve secret metadata. This can be based on the the user's role.         |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+


.. _put_secret_metadata:

PUT /v1/secrets/{uuid}/metadata
################################
Sets the metadata for a secret. Any metadata that was previously set will be deleted and
replaced with this metadata.

Parameters
**********

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| metadata | list    | Contains a list of the secret metadata's key/value pairs.    |
|          |         | The provided keys must be lowercase. If not they will be     |
|          |         | converted to lowercase.                                      |
+----------+---------+--------------------------------------------------------------+

Request:
********

.. code-block:: javascript

    PUT /v1/secrets/{uuid}/metadata
    Headers:
        Content-Type: application/json
        X-Auth-Token: <token>

    Content:
    {
      'metadata': {
          'description': 'contains the AES key',
          'geolocation': '12.3456, -98.7654'
        }
    }

Response:
*********

.. code-block:: javascript

    201 OK
    {
        "metadata_ref": "https://{barbican_host}/v1/secrets/{secret_uuid}/metadata"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successfully created/updated Secret Metadata                                |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource.                                                                   |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | create secret metadata. This can be based on the the user's role.           |
+------+-----------------------------------------------------------------------------+

.. _get_secret_metadatum:

GET /v1/secrets/{uuid}/metadata/{key}
#####################################
Retrieves a secret's user-added metadata.

Request:
*****************

.. code-block:: javascript

    GET /v1/secrets/{uuid}/metadata/{key}
    Headers:
        Accept: application/json
        X-Auth-Token: <token>

Response:
******************

.. code-block:: javascript

    200 OK
    {
      "key": "access-limit",
      "value": "0"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource                                                                    |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | retrieve secret metadata. This can be based on the the user's role.         |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+

.. _post_secret_metadatum:

POST /v1/secrets/{uuid}/metadata/
#################################

Adds a new key/value pair to the secret's user metadata. The key sent in the
request must not already exist in the metadata. The key must also be in
lowercase, otherwise it will automatically be changed to lowercase.


Request:
********

.. code-block:: javascript

    POST /v1/secrets/{uuid}/metadata/
    Headers:
        X-Auth-Token: <token>
        Content-Type: application/json

    Content:
      {
        "key": "access-limit",
        "value": "11"
      }

Response:
*********

.. code-block:: javascript

  201 Created
  Secret Metadata Location: http://example.com:9311/v1/secrets/{uuid}/metadata/access-limit
    {
      "key": "access-limit",
      "value": "11"
    }

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource.                                                                   |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | create secret metadata. This can be based on the the user's role.           |
+------+-----------------------------------------------------------------------------+
| 409  | Conflict. The provided metadata key already exists.                         |
+------+-----------------------------------------------------------------------------+


.. _put_secret_metadatum:

PUT /v1/secrets/{uuid}/metadata/{key}
#####################################

Updates an existing key/value pair in the secret's user metadata. The key sent
in the request must already exist in the metadata. The key must also be
in lowercase, otherwise it will automatically be changed to lowercase.


Request:
********

.. code-block:: javascript

    PUT /v1/secrets/{uuid}/metadata/{key}
    Headers:
        X-Auth-Token: <token>
        Content-Type: application/json

    Content:
      {
        "key": "access-limit",
        "value": "11"
      }

Response:
*********

.. code-block:: javascript

  200 OK

  {
    "key": "access-limit",
    "value": "11"
  }

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource.                                                                   |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | update secret metadata. This can be based on the the user's role.           |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+

.. _delete_secret_metadatum:

DELETE /v1/secrets/{uuid}/metadata/{key}
########################################

Delete secret metadata by key.

Request:
********

.. code-block:: javascript

    DELETE /v1/secrets/{uuid}/metadata/{key}
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
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to access this   |
|      | resource.                                                                   |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | delete secret metdata. This can be based on the the user's role.            |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+
