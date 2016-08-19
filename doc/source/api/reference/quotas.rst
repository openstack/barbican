**********************
Quotas API - Reference
**********************

GET /v1/quotas
##############
Get the effective quotas for the project of the requester. The project id
of the requester is derived from the authentication token provided in the
X-Auth-Token header.

.. _get_quotas_request:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/quotas
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {
            "quotas": {
              "secrets": 10,
              "orders": 20,
              "containers": 10,
              "consumers": -1,
              "cas": 5
            }
          }


.. _get_quotas_response_attributes:

Response Attributes
*******************

+------------+---------+--------------------------------------------------------------+
| Name       | Type    | Description                                                  |
+============+=========+==============================================================+
| quotas     | dict    | Contains a dictionary with quota information                 |
+------------+---------+--------------------------------------------------------------+
| secrets    | integer | Contains the effective quota value of the current project    |
|            |         | for the secret resource.                                     |
+------------+---------+--------------------------------------------------------------+
| orders     | integer | Contains the effective quota value of the current project    |
|            |         | for the orders resource.                                     |
+------------+---------+--------------------------------------------------------------+
| containers | integer | Contains the effective quota value of the current project    |
|            |         | for the containers resource.                                 |
+------------+---------+--------------------------------------------------------------+
| consumers  | integer | Contains the effective quota value of the current project    |
|            |         | for the consumers resource.                                  |
+------------+---------+--------------------------------------------------------------+
| cas        | integer | Contains the effective quota value of the current project    |
|            |         | for the CAs resource.                                        |
+------------+---------+--------------------------------------------------------------+

Effective quota values are interpreted as follows:

+-------+-----------------------------------------------------------------------------+
| Value | Description                                                                 |
+=======+=============================================================================+
|  -1   | A negative value indicates the resource is unconstrained by a quota.        |
+-------+-----------------------------------------------------------------------------+
|   0   | A zero value indicates that the resource is disabled.                       |
+-------+-----------------------------------------------------------------------------+
| int   | A positive value indicates the maximum number of that resource that can be  |
|       | created for the current project.                                            |
+-------+-----------------------------------------------------------------------------+

.. _get_quotas_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+

.. _get_project_quotas:

GET /v1/project-quotas
######################
Gets a list of configured project quota records.  Paging is supported using the
optional parameters offset and limit.

.. _get_project_quotas_request:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/project-quotas
          Headers:
            X-Auth-Token:<token>
            Accept: application/json

        Response:

          200 OK

          Content-Type: application/json

          {
            "project_quotas": [
              {
                "project_id": "1234",
                "project_quotas": {
                     "secrets": 2000,
                     "orders": 0,
                     "containers": -1,
                     "consumers": null,
                     "cas": null
                 }
              },
              {
                "project_id": "5678",
                "project_quotas": {
                     "secrets": 200,
                     "orders": 100,
                     "containers": -1,
                     "consumers": null,
                     "cas": null
                 }
              },
            ],
            "total" : 30,
          }


.. _get_project_quotas_parameters:

Parameters
**********

+--------+---------+----------------------------------------------------------------+
| Name   | Type    | Description                                                    |
+========+=========+================================================================+
| offset | integer | The starting index within the total list of the project        |
|        |         | quotas that you would like to receive.                         |
+--------+---------+----------------------------------------------------------------+
| limit  | integer | The maximum number of records to return.                       |
+--------+---------+----------------------------------------------------------------+

.. _get_project_quotas_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| project-id     | string  | The UUID of a project with configured quota information.     |
+----------------+---------+--------------------------------------------------------------+
| project-quotas | dict    | Contains a dictionary with project quota information.        |
+----------------+---------+--------------------------------------------------------------+
| secrets        | integer | Contains the effective quota value of the current project    |
|                |         | for the secret resource.                                     |
+----------------+---------+--------------------------------------------------------------+
| orders         | integer | Contains the effective quota value of the current project    |
|                |         | for the orders resource.                                     |
+----------------+---------+--------------------------------------------------------------+
| containers     | integer | Contains the effective quota value of the current project    |
|                |         | for the containers resource.                                 |
+----------------+---------+--------------------------------------------------------------+
| consumers      | integer | Contains the effective quota value of the current project    |
|                |         | for the consumers resource.                                  |
+----------------+---------+--------------------------------------------------------------+
| cas            | integer | Contains the effective quota value of the current project    |
|                |         | for the CAs resource.                                        |
+----------------+---------+--------------------------------------------------------------+
| total          | integer | The total number of configured project quotas records.       |
+----------------+---------+--------------------------------------------------------------+
| next           | string  | A HATEOAS URL to retrieve the next set of quotas based on    |
|                |         | the offset and limit parameters. This attribute is only      |
|                |         | available when the total number of secrets is greater than   |
|                |         | offset and limit parameter combined.                         |
+----------------+---------+--------------------------------------------------------------+
| previous       | string  | A HATEOAS URL to retrieve the previous set of quotas based   |
|                |         | on the offset and limit parameters. This attribute is only   |
|                |         | available when the request offset is greater than 0.         |
+----------------+---------+--------------------------------------------------------------+

Configured project quota values are interpreted as follows:

+-------+-----------------------------------------------------------------------------+
| Value | Description                                                                 |
+=======+=============================================================================+
|  -1   | A negative value indicates the resource is unconstrained by a quota.        |
+-------+-----------------------------------------------------------------------------+
|   0   | A zero value indicates that the resource is disabled.                       |
+-------+-----------------------------------------------------------------------------+
| int   | A positive value indicates the maximum number of that resource that can be  |
|       | created for the current project.                                            |
+-------+-----------------------------------------------------------------------------+
| null  | A null value indicates that the default quota value for the resource        |
|       | will be used as the quota for this resource in the current project.         |
+-------+-----------------------------------------------------------------------------+

.. _get_project_quotas_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+

.. _get_project_quotas_uuid:

GET /v1/project-quotas/{uuid}
#############################
Retrieves a project's configured project quota information.

.. _get_project_quotas_uuid_request:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/project-quotas/{uuid}
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          200 OK

          Content-Type: application/json

          {
            "project_quotas": {
              "secrets": 10,
              "orders": 20,
              "containers": -1,
              "consumers": 10,
              "cas": 5
            }
          }


.. _get_project_quotas_uuid_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| project-quotas | dict    | Contains a dictionary with project quota information.        |
+----------------+---------+--------------------------------------------------------------+
| secrets        | integer | Contains the configured quota value of the requested project |
|                |         | for the secret resource.                                     |
+----------------+---------+--------------------------------------------------------------+
| orders         | integer | Contains the configured quota value of the requested project |
|                |         | for the orders resource.                                     |
+----------------+---------+--------------------------------------------------------------+
| containers     | integer | Contains the configured quota value of the requested project |
|                |         | for the containers resource.                                 |
+----------------+---------+--------------------------------------------------------------+
| consumers      | integer | Contains the configured quota value of the requested project |
|                |         | for the consumers resource.                                  |
+----------------+---------+--------------------------------------------------------------+
| cas            | integer | Contains the configured quota value of the requested project |
|                |         | for the CAs resource.                                        |
+----------------+---------+--------------------------------------------------------------+

.. _get_project_quotas_uuid_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 404  | Not Found.  The requested project does not have any configured quotas.      |
+------+-----------------------------------------------------------------------------+

.. _put_project_quotas:

PUT /v1/project-quotas/{uuid}
#############################

Create or update the configured project quotas for the project with the specified UUID.

.. _put_project_quotas_request:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          PUT /v1/project-quotas/{uuid}
          Headers:
            X-Auth-Token:<token>
            Content-Type: application/json

          Body::

            {
              "project_quotas": {
                "secrets": 50,
                "orders": 10,
                "containers": 20
              }
            }


        Response:

          204 OK

.. _put_project_quotas_request_attributes:

Request Attributes
******************

+----------------+---------+----------------------------------------------+
| Attribute Name | Type    | Description                                  |
+================+=========+==============================================+
| project-quotas | dict    | A dictionary with project quota information. |
+----------------+---------+----------------------------------------------+
| secrets        | integer | The value to set for this project's secret   |
|                |         | quota.                                       |
+----------------+---------+----------------------------------------------+
| orders         | integer | The value to set for this project's order    |
|                |         | quota.                                       |
+----------------+---------+----------------------------------------------+
| containers     | integer | The value to set for this project's          |
|                |         | container quota.                             |
+----------------+---------+----------------------------------------------+
| consumers      | integer | The value to set for this project's          |
|                |         | consumer quota.                              |
+----------------+---------+----------------------------------------------+
| cas            | integer | The value to set for this project's          |
|                |         | CA quota.                                    |
+----------------+---------+----------------------------------------------+

Configured project quota values are specified as follows:

+-------+-----------------------------------------------------------------------------+
| Value | Description                                                                 |
+=======+=============================================================================+
|  -1   | A negative value indicates the resource is unconstrained by a quota.        |
+-------+-----------------------------------------------------------------------------+
|   0   | A zero value indicates that the resource is disabled.                       |
+-------+-----------------------------------------------------------------------------+
| int   | A positive value indicates the maximum number of that resource that can be  |
|       | created for the specified project.                                          |
+-------+-----------------------------------------------------------------------------+
|       | If a value is not given for a resource, this indicates that the default     |
|       | quota should be used for that resource for the specified project.           |
+-------+-----------------------------------------------------------------------------+

.. _put_project_quotas_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+

.. _delete_project_quotas:

DELETE /v1/project-quotas/{uuid}
################################

Delete the project quotas configuration for the project with the requested UUID. When
the project quota configuration is deleted, then the default quotas will be used for
the specified project.

.. _delete_project_request:

Request/Response:
*****************

.. code-block:: javascript

    Request:

      DELETE v1/project-quotas/{uuid}
      Headers:
        X-Auth-Token:<token>


    Response:

      204 No Content


.. _delete_project_quotas_status_codes:

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
