**************************
Containers API - Reference
**************************

GET /v1/containers
##################

Lists a project's containers.

Returned containers will be ordered by creation date; oldest to newest.

Parameters
**********

+--------+---------+------------------------------------------------------------+
| Name   | Type    | Description                                                |
+========+=========+============================================================+
| offset | integer | The starting index within the total list of the containers |
|        |         | that you would like to retrieve.                           |
+--------+---------+------------------------------------------------------------+
| limit  | integer | The maximum number of containers to return (up to 100).    |
|        |         | The default limit is 10.                                   |
+--------+---------+------------------------------------------------------------+

Response Attributes
*******************

+------------+---------+--------------------------------------------------------+
| Name       | Type    | Description                                            |
+============+=========+========================================================+
| containers | list    | Contains a list of dictionaries filled with container  |
|            |         | data                                                   |
+------------+---------+--------------------------------------------------------+
| total      | integer | The total number of containers available to the user   |
+------------+---------+--------------------------------------------------------+
| next       | string  | A HATEOAS url to retrieve the next set of containers   |
|            |         | based on the offset and limit parameters. This         |
|            |         | attribute is only available when the total number of   |
|            |         | containers is greater than offset and limit parameter  |
|            |         | combined.                                              |
+------------+---------+--------------------------------------------------------+
| previous   | string  | A HATEOAS url to retrieve the previous set of          |
|            |         | containers based on the offset and limit parameters.   |
|            |         | This attribute is only available when the request      |
|            |         | offset is greater than 0.                              |
+------------+---------+--------------------------------------------------------+

Request:
********

.. code-block:: javascript

    GET /v1/containers
    Headers:
        X-Auth-Token: <token>


Response:
********

.. code-block:: javascript

    {
        "containers": [
            {
                "consumers": [],
                "container_ref": "https://{barbican_host}/v1/containers/{uuid}",
                "created": "2015-03-26T21:10:45.417835",
                "name": "container name",
                "secret_refs": [
                    {
                        "name": "private_key",
                        "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
                    }
                ],
                "status": "ACTIVE",
                "type": "generic",
                "updated": "2015-03-26T21:10:45.417835"
            }
        ],
        "total": 1
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+

GET /v1/containers/{uuid}
#########################

Retrieves a single container.

Response Attributes
*******************

+-------------+--------+---------------------------------------------------------+
| Name        | Type   | Description                                             |
+=============+========+=========================================================+
| name        | string | (optional) Human readable name for the container        |
+-------------+--------+---------------------------------------------------------+
| type        | string | Type of container. Options: generic, rsa, certificate   |
+-------------+--------+---------------------------------------------------------+
| secret_refs | list   | A list of dictionaries containing references to secrets |
+-------------+--------+---------------------------------------------------------+

Request:
********

.. code-block:: javascript

    GET /v1/containers/{uuid}
    Headers:
        X-Auth-Token: <token>

Response:
*********

.. code-block:: javascript

    {
        "type": "generic",
        "status": "ACTIVE",
        "name": "container name",
        "consumers": [],
        "container_ref": "https://{barbican_host}/v1/containers/{uuid}",
        "secret_refs": [
            {
                "name": "private_key",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            }
        ],
        "created": "2015-03-26T21:10:45.417835",
        "updated": "2015-03-26T21:10:45.417835"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found or unavailable                                          |
+------+-----------------------------------------------------------------------------+


POST /v1/containers
###################

Create a container

There are three different types of containers that can be created: generic,
rsa, and certificate.

**Generic**

This type of container holds any number of references to secrets. Each secret
reference is accompanied by a name. Unlike other container types, no specific
restrictions are enforced on the contents name attribute.

**RSA**

This type of container is designed to hold references to only three different
secrets. These secrets are enforced by the their accompanied names: public_key,
private_key, and private_key_passphrase.

**Certificate**

This type of container is designed to hold a reference to a certificate and
optionally private_key, private_key_passphrase, and intermediates.

Request Attributes
******************

+-------------+--------+-----------------------------------------------------------+
| Name        | Type   | Description                                               |
+=============+========+===========================================================+
| name        | string | (optional) Human readable name for identifying your       |
|             |        | container                                                 |
+-------------+--------+-----------------------------------------------------------+
| type        | string | Type of container. Options: generic, rsa, certificate     |
+-------------+--------+-----------------------------------------------------------+
| secret_refs | list   | A list of dictionaries containing references to secrets   |
+-------------+--------+-----------------------------------------------------------+

Request:
********

.. code-block:: javascript

    POST /v1/containers
    Headers:
        X-Auth-Token: <token>

    Content:
    {
        "type": "generic",
        "name": "container name",
        "secret_refs": [
            {
                "name": "private_key",
                "secret_ref": "https://{barbican_host}/v1/secrets/{secret_uuid}"
            }
        ]
    }


Response:
*********

.. code-block:: javascript

    {
        "container_ref": "https://{barbican_host}/v1/containers/{container_uuid}"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successful creation of the container                                        |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden.  The user has been authenticated, but is not authorized to       |
|      | create a container.  This can be based on the the user's role or the        |
|      | project's quota.                                                            |
+------+-----------------------------------------------------------------------------+


DELETE /v1/containers/{uuid}
############################

Deletes a container

Request:
********

.. code-block:: javascript

    DELETE /v1/containers/{container_uuid}
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
| 204  | Successful deletion of a container                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found or unavailable                                          |
+------+-----------------------------------------------------------------------------+
