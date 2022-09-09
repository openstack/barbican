********************************
Secret consumers API - Reference
********************************

GET {secret_ref}/consumers
##########################
Lists a secret's consumers.

The list of consumers can be filtered by the parameters passed in via the URL.

.. _secret_consumer_list_parameters:

Parameters
**********

+----------+---------+----------------------------------------------------------------+
| Name     | Type    | Description                                                    |
+==========+=========+================================================================+
| offset   | integer | The starting index within the total list of the consumers that |
|          |         | you would like to retrieve.                                    |
+----------+---------+----------------------------------------------------------------+
| limit    | integer | The maximum number of records to return (up to 100). The       |
|          |         | default limit is 10.                                           |
+----------+---------+----------------------------------------------------------------+


Request:
********

.. code-block:: javascript

    GET {secret_ref}/consumers
    Headers:
        X-Auth-Token: <token>

Response:
*********

.. code-block:: javascript

    200 OK

    {
        "total": 3,
        "consumers": [
            {
                "created": "2015-10-15T21:06:33.123872",
                "updated": "2015-10-15T21:06:33.123878",
                "status": "ACTIVE",
                "service": "image",
                "resource_type": "image",
                "resource_id": "123e4567-e89b-12d3-a456-426614174001"
            },
            {
                "created": "2015-10-15T21:17:08.092408",
                "updated": "2015-10-15T21:17:08.092416",
                "status": "ACTIVE",
                "service": "volume",
                "resource_type": "volume",
                "resource_id": "123e4567-e89b-12d3-a456-426614174002"
            },
            {
                "created": "2015-10-15T21:21:29.970365",
                "updated": "2015-10-15T21:21:29.970370",
                "status": "ACTIVE",
                "service": "load-balancer",
                "resource_type": "listener",
                "resource_id": "123e4567-e89b-12d3-a456-426614174003"
            }
        ]
    }

Request:
********

.. code-block:: console

    GET {secret_ref}/consumers?limit=1&offset=1
    Headers:
        X-Auth-Token: <token>

.. code-block:: javascript

    {
        "total": 3,
        "next": "http://localhost:9311/v1/secrets/{secret_ref}/consumers?limit=1&offset=2",
        "consumers": [
            {
                "created": "2015-10-15T21:17:08.092408",
                "updated": "2015-10-15T21:17:08.092416",
                "status": "ACTIVE",
                "service": "volume",
                "resource_type": "volume",
                "resource_id": "123e4567-e89b-12d3-a456-426614174002"
            }
        ],
        "previous": "http://localhost:9311/v1/secrets/{secret_ref}/consumers?limit=1&offset=0"
    }

.. _secret_consumer_response_attributes:

Response Attributes
*******************

+-----------+---------+----------------------------------------------------------------+
| Name      | Type    | Description                                                    |
+===========+=========+================================================================+
| consumers | list    | Contains a list of dictionaries filled with consumer metadata. |
+-----------+---------+----------------------------------------------------------------+
| total     | integer | The total number of consumers available to the user.           |
+-----------+---------+----------------------------------------------------------------+
| next      | string  | A HATEOAS URL to retrieve the next set of consumers based on   |
|           |         | the offset and limit parameters. This attribute is only        |
|           |         | available when the total number of consumers is greater than   |
|           |         | offset and limit parameter combined.                           |
+-----------+---------+----------------------------------------------------------------+
| previous  | string  | A HATEOAS URL to retrieve the previous set of consumers based  |
|           |         | on the offset and limit parameters. This attribute is only     |
|           |         | available when the request offset is greater than 0.           |
+-----------+---------+----------------------------------------------------------------+


.. _secret_consumer_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | OK.                                                                         |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource.|
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden.  The user has been authenticated, but is not authorized to       |
|      | list consumers. This can be based on the user's role.                       |
+------+-----------------------------------------------------------------------------+

.. _post_secret_consumers:

POST {secret_ref}/consumers
###########################

Creates a consumer

Attributes
**********

+--------------------+---------+---------------------------------------------------------+------------+
| Attribute Name     | Type    | Description                                             | Default    |
+====================+=========+=========================================================+============+
| service            | string  | Consumer’s OpenStack service type. Each service should  | None       |
|                    |         | preferably use it's reserved name, as shown in:         |            |
|                    |         | https://service-types.openstack.org/service-types.json  |            |
+--------------------+---------+---------------------------------------------------------+------------+
| resource_type      | string  | Name of the resource type using the secret              | None       |
|                    |         |  e.g. “images” or “lbaas/loadbalancers”                 |            |
+--------------------+---------+---------------------------------------------------------+------------+
| resource_id        | string  | Unique identifier for the resource using this secret.   | None       |
+--------------------+---------+---------------------------------------------------------+------------+

Request:
********

.. code-block:: javascript

    POST {secret_ref}/consumers
    Headers:
        X-Auth-Token: <token>
        Content-Type: application/json

    Content:
    {
        "service": "image",
        "resource_type": "image",
        "resource_id": "123e4567-e89b-12d3-a456-426614174000"
    }

Response:
*********

.. code-block:: javascript

    200 OK

    {
        "status": "ACTIVE",
        "updated": "2015-10-15T17:56:18.626724",
        "name": "secret name",
        "consumers": [
            {
                "service": "image",
                "resource_type": "image",
                "resource_id": "123e4567-e89b-12d3-a456-426614174000"
            }
        ],
        "created": "2015-10-15T17:55:44.380002",
        "secret_ref": "http://localhost:9311/v1/secrets/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9",
        "creator_id": "b17c815d80f946ea8505c34347a2aeba",
        "secret_type": "opaque",
        "expiration": null,
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | OK.                                                                         |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource.|
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden. The user has been authenticated, but is not authorized to        |
|      | create a consumer. This can be based on the user's role or the              |
|      | project's quota.                                                            |
+------+-----------------------------------------------------------------------------+


.. _delete_secret_consumer:

DELETE {secret_ref}/consumers
#############################

Delete a consumer.

Attributes
**********

+--------------------+---------+---------------------------------------------------------+------------+
| Attribute Name     | Type    | Description                                             | Default    |
+====================+=========+=========================================================+============+
| service            | string  | Consumer’s OpenStack service type as shown in           | None       |
|                    |         | https://service-types.openstack.org/service-types.json  |            |
+--------------------+---------+---------------------------------------------------------+------------+
| resource_type      | string  | Name of the resource type using the secret              | None       |
|                    |         |  e.g. “images” or “lbaas/loadbalancers”                 |            |
+--------------------+---------+---------------------------------------------------------+------------+
| resource_id        | string  | Unique identifier for the resource using this secret.   | None       |
+--------------------+---------+---------------------------------------------------------+------------+

Request:
********

.. code-block:: javascript

    DELETE {secret_ref}/consumers
    Headers:
        X-Auth-Token: <token>
        Content-Type: application/json

    Content:
    {
        "service": "image",
        "resource_type": "image",
        "resource_id": "123e4567-e89b-12d3-a456-426614174000"
    }


Response:
*********

.. code-block:: javascript

    200 OK

    {
        "status": "ACTIVE",
        "updated": "2015-10-15T17:56:18.626724",
        "name": "secret name",
        "consumers": [],
        "created": "2015-10-15T17:55:44.380002",
        "secret_ref": "http://localhost:9311/v1/secrets/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9",
        "creator_id": "b17c815d80f946ea8505c34347a2aeba",
        "secret_type": "opaque",
        "expiration": null,
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | OK.                                                                         |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource.|
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden.  The user has been authenticated, but is not authorized to       |
|      | delete a consumer. This can be based on the user's role.                    |
+------+-----------------------------------------------------------------------------+
| 404  | Consumer Not Found.                                                         |
+------+-----------------------------------------------------------------------------+
