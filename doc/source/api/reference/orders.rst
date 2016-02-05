**********************
Orders API - Reference
**********************

.. _get_orders:

GET /v1/orders
##############
Lists a project's orders.

The list of orders can be filtered by the parameters passed in via the URL.

.. _get_order_parameters:

Parameters
**********

+----------+---------+----------------------------------------------------------------+
| Name     | Type    | Description                                                    |
+==========+=========+================================================================+
| offset   | integer | The starting index within the total list of the orders that    |
|          |         | you would like to retrieve. (Default is 0)                     |
+----------+---------+----------------------------------------------------------------+
| limit    | integer | The maximum number of records to return (up to 100).           |
|          |         | (Default is 10)                                                |
+----------+---------+----------------------------------------------------------------+

.. _get_orders_request:

Request:
********

.. code-block:: javascript

    GET /v1/orders
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token}

.. _get_orders_response:

Response:
*********

.. code-block:: none

    200 Success

    {
        "orders": [
        {
            "created": "2015-10-20T18:38:44",
            "creator_id": "40540f978fbd45c1af18910e3e02b63f",
            "meta": {
                "algorithm": "AES",
                "bit_length": 256,
                "expiration": null,
                "mode": "cbc",
                "name": "secretname",
                "payload_content_type": "application/octet-stream"
            },
            "order_ref": "http://localhost:9311/v1/orders/2284ba6f-f964-4de7-b61e-c413df5d1e47",
            "secret_ref": "http://localhost:9311/v1/secrets/15dcf8e4-3138-4360-be9f-fc4bc2e64a19",
            "status": "ACTIVE",
            "sub_status": "Unknown",
            "sub_status_message": "Unknown",
            "type": "key",
            "updated": "2015-10-20T18:38:44"
        },
        {
            "created": "2015-10-20T18:38:47",
            "creator_id": "40540f978fbd45c1af18910e3e02b63f",
            "meta": {
                "algorithm": "AES",
                "bit_length": 256,
                "expiration": null,
                "mode": "cbc",
                "name": "secretname",
                "payload_content_type": "application/octet-stream"
            },
            "order_ref": "http://localhost:9311/v1/orders/87b7169e-3aa2-4cb1-8800-b5aadf6babd1",
            "secret_ref": "http://localhost:9311/v1/secrets/80183f4b-c0de-4a94-91ad-6d55251acee2",
            "status": "ACTIVE",
            "sub_status": "Unknown",
            "sub_status_message": "Unknown",
            "type": "key",
            "updated": "2015-10-20T18:38:47"
        }
    ],
    "total": 2
}


.. _get_order_response_attributes:

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| orders   | list    | Contains a list of dictionaries filled with order metadata.  |
+----------+---------+--------------------------------------------------------------+
| total    | integer | The total number of orders available to the user.            |
+----------+---------+--------------------------------------------------------------+
| next     | string  | A HATEOS url to retrieve the next set of objects based on    |
|          |         | the offset and limit parameters. This attribute is only      |
|          |         | available when the total number of objects is greater than   |
|          |         | offset and limit parameter combined.                         |
+----------+---------+--------------------------------------------------------------+
| previous | string  | A HATEOS url to retrieve the previous set of objects based   |
|          |         | on the offset and limit parameters. This attribute is only   |
|          |         | available when the request offset is greater than 0.         |
+----------+---------+--------------------------------------------------------------+

.. _get_order_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+

.. _post_orders:

POST /v1/orders
###############
Creates an order

Parameters
**********

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| type                       | string  | The type of key to be generated. Valid types | None       |
|                            |         | are key, asymmetric, and certificate         |            |
+----------------------------+---------+----------------------------------------------+------------+
| meta                       |         | Dictionary containing the secret metadata    | None       |
|                            | dict    | used to generate the secret.                 |            |
|                            |         |                                              |            |
+----------------------------+---------+----------------------------------------------+------------+

.. _post_orders_request:

Request:
********

.. code-block:: javascript

    POST /v1/orders
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token}

    Content:
    {
        "type":"key",
        "meta":
            {
                "name":"secretname",
                "algorithm": "AES",
                "bit_length": 256,
                "mode": "cbc",
                "payload_content_type":"application/octet-stream"
            }
    }

.. _post_orders_response:

Response:
*********

.. code-block:: none

    202 Created

    {
        "order_ref": "http://{barbican_host}/v1/orders/{order_uuid}"
    }

.. _post_orders_response_attributes:

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| order_ref|  string | Order reference                                              |
+----------+---------+--------------------------------------------------------------+

.. _post_orders_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 202  | Successfully created an order                                               |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported media-type                                                      |
+------+-----------------------------------------------------------------------------+

.. _get_unique_order_metadata:

GET /v1/orders/{uuid}
#####################
Retrieves an order's metadata

.. _get_unique_order_request:

Request:
********

.. code-block:: javascript

    GET /v1/orders/{order_uuid}
    Headers:
        Accept: application/json
        X-Auth-Token: {token}

Parameters
**********

None

.. _get_unique_order_response:

Response:
*********

.. code-block:: javascript

    200 Success

    {
        "created": "2015-10-20T18:49:02",
        "creator_id": "40540f978fbd45c1af18910e3e02b63f",
        "meta": {
            "algorithm": "AES",
            "bit_length": 256,
            "expiration": null,
            "mode": "cbc",
            "name": "secretname",
            "payload_content_type": "application/octet-stream"
        },
        "order_ref": "http://localhost:9311/v1/orders/5443d349-fe0c-4bfd-bd9d-99c4a9770638",
        "secret_ref": "http://localhost:9311/v1/secrets/16f8d4f3-d3dd-4160-a5bd-8e5095a42613",
        "status": "ACTIVE",
        "sub_status": "Unknown",
        "sub_status_message": "Unknown",
        "type": "key",
        "updated": "2015-10-20T18:49:02"
    }

.. _get_unique_order_response_attributes:

Response Attributes
*******************


+--------------------+---------+----------------------------------------------------+
| Name               | Type    | Description                                        |
+====================+=========+====================================================+
| created            | string  | Timestamp in ISO8601 format of when the order was  |
|                    |         | created                                            |
+--------------------+---------+----------------------------------------------------+
| creator_id         | string  | Keystone Id of the user who created the order      |
+--------------------+---------+----------------------------------------------------+
| meta               | dict    | Secret metadata used for informational purposes    |
+--------------------+---------+----------------------------------------------------+
| order_ref          | string  | Order href associated with the order               |
+--------------------+---------+----------------------------------------------------+
| secret_ref         | string  | Secret href associated with the order              |
+--------------------+---------+----------------------------------------------------+
| status             | string  | Current status of the order                        |
+--------------------+---------+----------------------------------------------------+
| sub_status         | string  | Metadata associated with the order                 |
+--------------------+---------+----------------------------------------------------+
| sub_status_message | string  | Metadata associated with the order                 |
+--------------------+---------+----------------------------------------------------+
| type               | string  | Indicates the type of order                        |
+--------------------+---------+----------------------------------------------------+
| updated            | string  | Timestamp in ISO8601 format of the last time the   |
|                    |         | order was updated.                                 |
+--------------------+---------+----------------------------------------------------+

.. _get_unique_orders_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully retrieved the order                                            |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+

.. _delete_unique_order:

DELETE /v1/orders/{uuid}
########################
Delete an order

.. _delete_order_request:

Request:
********

.. code-block:: javascript

    DELETE /v1/orders/{order_uuid}
    Headers:
        X-Auth-Token: {token}


Parameters
**********

None

.. _delete_order_response:

Response:
*********

.. code-block:: javascript

    204 Success


.. _delete_order_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successfully deleted the order                                              |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found                                                                   |
+------+-----------------------------------------------------------------------------+