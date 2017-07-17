*****************************
Secret Stores API - Reference
*****************************

Barbican provides API to manage secret stores available in a deployment. APIs
are provided for listing available secret stores and to manage project level
secret store mapping. There are two types of secret stores. One is global
default secret store which is used for all projects. And then project
`preferred` secret store which is used to store all *new* secrets created in
that project. For an introduction to multiple store backends support, see
:doc:`Using Multiple Secret Store Plugins </configuration/plugin_backends>` . This
document will focus on the details of the Barbican `/v1/secret-stores` REST API.

When multiple secret store backends support is not enabled in service
configuration, then all of these API will return resource not found (http
status code 404) error. Error message text will highlight that the support is
not enabled in configuration.

GET /v1/secret-stores
#####################
Project administrator can request list of available secret store backends.
Response contains list of secret stores which are currently configured in
barbican deployment. If multiple store backends support is not enabled, then
list will return resource not found (404) error.

.. _get_secret_stores_request_response:

Request/Response:
*****************

.. code-block:: javascript

      Request:

         GET /secret-stores
         Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"
            Accept: application/json

        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

         {
            "secret_stores":[
               {
                  "status": "ACTIVE",
                  "updated": "2016-08-22T23:46:45.114283",
                  "name": "PKCS11 HSM",
                  "created": "2016-08-22T23:46:45.114283",
                  "secret_store_ref": "http://localhost:9311/v1/secret-stores/4d27b7a7-b82f-491d-88c0-746bd67dadc8",
                  "global_default": True,
                  "crypto_plugin": "p11_crypto",
                  "secret_store_plugin": "store_crypto"
               },
               {
                  "status": "ACTIVE",
                  "updated": "2016-08-22T23:46:45.124554",
                  "name": "KMIP HSM",
                  "created": "2016-08-22T23:46:45.124554",
                  "secret_store_ref": "http://localhost:9311/v1/secret-stores/93869b0f-60eb-4830-adb9-e2f7154a080b",
                  "global_default": False,
                  "crypto_plugin": None,
                  "secret_store_plugin": "kmip_plugin"
               },
               {
                  "status": "ACTIVE",
                  "updated": "2016-08-22T23:46:45.127866",
                  "name": "Software Only Crypto",
                  "created": "2016-08-22T23:46:45.127866",
                  "secret_store_ref": "http://localhost:9311/v1/secret-stores/0da45858-9420-42fe-a269-011f5f35deaa",
                  "global_default": False,
                  "crypto_plugin": "simple_crypto",
                  "secret_store_plugin": "store_crypto"
               }
         }


.. _get_secret_stores_response_attributes:

Response Attributes
*******************

+---------------+--------+---------------------------------------------+
| Name          | Type   | Description                                 |
+===============+========+=============================================+
| secret_stores | list   | A list of secret store references           |
+---------------+--------+---------------------------------------------+
| name          | string | store and crypto plugin name delimited by + |
|               |        | (plus) sign.                                |
+---------------+--------+---------------------------------------------+
| secret_store  | string | URL for referencing a specific secret store |
| _ref          |        |                                             |
+---------------+--------+---------------------------------------------+

.. _get_secret_stores_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 200  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | Not Found. When multiple secret store backends support is not enabled.   |
+------+--------------------------------------------------------------------------+


GET /v1/secret-stores/{secret_store_id}
#######################################

A project administrator (user with admin role) can request details of secret
store by its ID. Returned response will highlight whether this secret store is
currently configured as global default or not.

.. _get_secret_stores_id_request_response:

Request/Response:
*****************

.. code-block:: javascript

      Request:
         GET /secret-stores/93869b0f-60eb-4830-adb9-e2f7154a080b
         Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"
            Accept: application/json

      Response:
         HTTP/1.1 200 OK
         Content-Type: application/json

         {
            "status": "ACTIVE",
            "updated": "2016-08-22T23:46:45.124554",
            "name": "KMIP HSM",
            "created": "2016-08-22T23:46:45.124554",
            "secret_store_ref": "http://localhost:9311/v1/secret-stores/93869b0f-60eb-4830-adb9-e2f7154a080b",
            "global_default": False,
            "crypto_plugin": None,
            "secret_store_plugin": "kmip_plugin"
         }


.. _get_secret_stores_id_response_attributes:

Response Attributes
*******************

+------------------+---------+---------------------------------------------------------------+
| Name             | Type    | Description                                                   |
+==================+=========+===============================================================+
| name             | string  | store and crypto plugin name delimited by '+' (plus) sign     |
+------------------+---------+---------------------------------------------------------------+
| global_default   | boolean | flag indicating if this secret store is global default or not |
+------------------+---------+---------------------------------------------------------------+
| status           | list    | Status of the secret store                                    |
+------------------+---------+---------------------------------------------------------------+
| updated          | time    | Date and time secret store was last updated                   |
+------------------+---------+---------------------------------------------------------------+
| created          | time    | Date and time secret store was created                        |
+------------------+---------+---------------------------------------------------------------+
| secret_store_ref | string  | URL for referencing a specific secret store                   |
+------------------+---------+---------------------------------------------------------------+


.. _get_secret_stores_id_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 200  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | Not Found. When multiple secret store backends support is not enabled or |
|      | that secret store id does not exist.                                     |
+------+--------------------------------------------------------------------------+

GET /v1/secret-stores/preferred
###############################

A project administrator (user with admin role) can request a reference to the
preferred secret store if assigned previously. When a preferred secret store is
set for a project, then new project secrets are stored using that store
backend. If multiple secret store support is not enabled, then this resource
will return 404 (Not Found) error.

.. _get_secret_stores_preferred_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/secret-stores/preferred
          Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {
            "status": "ACTIVE",
            "updated": "2016-08-22T23:46:45.114283",
            "name": "PKCS11 HSM",
            "created": "2016-08-22T23:46:45.114283",
            "secret_store_ref": "http://localhost:9311/v1/secret-stores/4d27b7a7-b82f-491d-88c0-746bd67dadc8",
            "global_default": True,
            "crypto_plugin": "p11_crypto",
            "secret_store_plugin": "store_crypto"
          }


.. _get_secret_stores_preferred_response_attributes:

Response Attributes
*******************

+------------------+--------+-----------------------------------------------+
| Name             | Type   | Description                                   |
+==================+========+===============================================+
| secret_store_ref | string | A URL that references a specific secret store |
+------------------+--------+-----------------------------------------------+

.. _get_secret_stores_preferred_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 200  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | Not found. No preferred secret store has been defined or multiple secret |
|      | store backends support is not enabled.                                   |
+------+--------------------------------------------------------------------------+

POST /v1/secret-stores/{secret_store_id}/preferred
##################################################

A project administrator can set a secret store backend to be preferred store
backend for his/her project. From there on, any new secret stored in that
project will use specified plugin backend for storage and reading thereafter.
Existing secret storage will not be impacted as each secret captures its plugin
backend information when initially stored. If multiple secret store support is
not enabled, then this resource will return 404 (Not Found) error.

.. _post_secret_stores_id_preferred_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/secret-stores/7776adb8-e865-413c-8ccc-4f09c3fe0213/preferred
          Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"

        Response:

          HTTP/1.1 204 No Content


.. _post_secret_stores_id_preferred_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 204  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | The requested entity was not found or multiple secret store backends     |
|      | support is not enabled.                                                  |
+------+--------------------------------------------------------------------------+


DELETE /v1/secret-stores/{secret_store_id}/preferred
####################################################

A project administrator can remove preferred secret store backend setting. If
multiple secret store support is not enabled, then this resource will return
404 (Not Found) error.

.. _delete_secret_stores_id_preferred_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          DELETE /v1/secret-stores/7776adb8-e865-413c-8ccc-4f09c3fe0213/preferred
          Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"

        Response:

          HTTP/1.1 204 No Content

.. _delete_secret_stores_id_preferred_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 204  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | The requested entity was not found or multiple secret store backends     |
|      | support is not enabled.                                                  |
+------+--------------------------------------------------------------------------+


GET /v1/secret-stores/global-default
####################################

A project or service administrator can request a reference to the secret
store that is used as default secret store backend for the deployment.

.. _get_secret_stores_global_default_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/secret-stores/global-default
          Headers:
            X-Auth-Token: "f9cf2d480ba3485f85bdb9d07a4959f1"
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

         {
            "status": "ACTIVE",
            "updated": "2016-08-22T23:46:45.114283",
            "name": "PKCS11 HSM",
            "created": "2016-08-22T23:46:45.114283",
            "secret_store_ref": "http://localhost:9311/v1/secret-stores/4d27b7a7-b82f-491d-88c0-746bd67dadc8",
            "global_default": True,
            "crypto_plugin": "p11_crypto",
            "secret_store_plugin": "store_crypto"
         }


.. _get_secret_stores_global_default_response_attributes:

Response Attributes
*******************

+------------------+--------+-----------------------------------------------+
| Name             | Type   | Description                                   |
+==================+========+===============================================+
| secret_store_ref | string | A URL that references a specific secret store |
+------------------+--------+-----------------------------------------------+

.. _get_secret_stores_global_default_status_codes:

HTTP Status Codes
*****************

+------+--------------------------------------------------------------------------+
| Code | Description                                                              |
+======+==========================================================================+
| 200  | Successful Request                                                       |
+------+--------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                  |
+------+--------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action |
+------+--------------------------------------------------------------------------+
| 404  | Not Found. When multiple secret store backends support is not enabled.   |
+------+--------------------------------------------------------------------------+

