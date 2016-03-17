*******************
ACL API - Reference
*******************

.. note::

    This feature is applicable only when Barbican is used in an authenticated
    pipeline i.e. integrated with Keystone.

.. note::

    Currently the access control list (ACL) settings defined for a container
    are not propagated down to associated secrets.

.. warning::

    This ACL documentation is work in progress and may change in near future.


Secret ACL API
===============

.. _get_secret_acl:

GET /v1/secrets/{uuid}/acl
##########################
Retrieve the ACL settings for a given secret.

If no ACL is defined for that secret, then
`Default ACL <http://developer.openstack.org/api-guide/key-manager/acls.html#default-acl>`__
is returned.

Request/Response (With ACL defined):
************************************

.. code-block:: javascript

    Request:

    GET /v1/secrets/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "updated":"2015-05-12T20:08:47.644264",
        "created":"2015-05-12T19:23:44.019168",
        "users":[
          {user_id1},
          {user_id2},
          .....
        ],
        "project-access":{project-access-flag}
      }
    }


Request/Response (With no ACL defined):
***************************************

.. code-block:: javascript

    Request:

    GET /v1/secrets/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "project-access": true
      }
    }



HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request.                                                         |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Secret not found for the given UUID.                                        |
+------+-----------------------------------------------------------------------------+

.. _put_secret_acl:

PUT /v1/secrets/{uuid}/acl
##########################
Create new or replaces existing ACL for a given secret.

This call is used to add new ACL for a secret. If the ACL is already set on a secret, this
method will replace it with the requested ACL settings. In case of create (first new explicit
ACL) or replace existing ACL, 200 is returned in both cases. To delete existing users from
an ACL definition, pass empty list [] for `users`.

Returns an ACL reference in success case.

Attributes
**********

The ACL resource detailed in this page allows access to individual secrets to be controlled.
This access is configured via operations on those secrets. Currently only the 'read' operation
(which includes GET REST actions) is supported.

+----------------------------+----------+-----------------------------------------------+----------+
| Attribute Name             | Type     | Description                                   | Default  |
+============================+==========+===============================================+==========+
| read                       | parent   | ACL data for read operation.                  | None     |
|                            | element  |                                               |          |
+----------------------------+----------+-----------------------------------------------+----------+
| users                      | [string] | (optional) List of user ids. This needs to be | []       |
|                            |          | a user id as returned by Keystone.            |          |
+----------------------------+----------+-----------------------------------------------+----------+
| project-access             | boolean  | (optional) Flag to mark a secret private so   | `true`   |
|                            |          | that the user who created the secret and      |          |
|                            |          | ``users`` specified in above list can only    |          |
|                            |          | access the secret. Pass `false` to mark the   |          |
|                            |          | secret private.                               |          |
+----------------------------+----------+-----------------------------------------------+----------+


Request/Response (Set or Replace ACL):
**************************************

.. code-block:: javascript

    Request:

    PUT /v1/secrets/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":{
        "users":[
          {user_id1},
          {user_id2},
          .....
        ],
        "project-access":{project-access-flag}
      }
    }

    Response:

    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/secrets/{uuid}/acl"}


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully set/replaced secret ACL.                                       |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Secret not found for the given UUID.                                        |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported Media Type.                                                     |
+------+-----------------------------------------------------------------------------+


.. _patch_secret_acl:

PATCH /v1/secrets/{uuid}/acl
############################

Updates existing ACL for a given secret. This method can be used to apply partial changes on
existing ACL settings. Client can update the `users` list and enable or disable `project-access`
flag for existing ACL. List of provided users replaces existing users if any. For an existing
list of provided users from an ACL definition, pass empty list [] for `users`.

Returns an ACL reference in success case.

.. note::
    
    PATCH API support will be changing in near future.

Attributes
**********

+----------------------------+----------+-----------------------------------------------+----------+
| Attribute Name             | Type     | Description                                   | Default  |
+============================+==========+===============================================+==========+
| read                       | parent   | ACL data for read operation.                  | None     |
|                            | element  |                                               |          |
+----------------------------+----------+-----------------------------------------------+----------+
| users                      | [string] | (optional) List of user ids. This needs to be | None     |
|                            |          | a user id as returned by Keystone.            |          |
+----------------------------+----------+-----------------------------------------------+----------+
| project-access             | boolean  | (optional) Flag to mark a secret private so   | None     |
|                            |          | that the user who created the secret and      |          |
|                            |          | ``users`` specified in above list can only    |          |
|                            |          | access the secret. Pass `false` to mark the   |          |
|                            |          | secret private.                               |          |
+----------------------------+----------+-----------------------------------------------+----------+

Request/Response (Updating project-access flag):
************************************************

.. code-block:: javascript

    PATCH /v1/secrets/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":
        {
          "project-access":false
        }
    }

    Response:
    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/secrets/{uuid}/acl"}


Request/Response (Removing all users from ACL):
***********************************************

.. code-block:: javascript

    PATCH /v1/secrets/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":
        {
          "users":[]
        }
    }

    Response:
    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/secrets/{uuid}/acl"}


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully updated secret ACL.                                            |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Secret not found for the given UUID.                                        |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported Media Type.                                                     |
+------+-----------------------------------------------------------------------------+

.. _delete_secret_acl:

DELETE /v1/secrets/{uuid}/acl
#############################

Delete ACL for a given secret. No content is returned in the case of successful
deletion.

Request/Response:
*****************

.. code-block:: javascript

    DELETE /v1/secrets/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:
    HTTP/1.1 200 OK


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully deleted secret ACL.                                            |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Secret not found for the given UUID.                                        |
+------+-----------------------------------------------------------------------------+

Container ACL API
=================

.. _get_container_acl:

GET /v1/containers/{uuid}/acl
#############################
Retrieve the ACL settings for a given container.

If no ACL is defined for that container, then
`Default ACL <http://developer.openstack.org/api-guide/key-manager/acls.html#default-acl>`__
is returned.

Request/Response (With ACL defined):
************************************

.. code-block:: javascript

    Request:

    GET /v1/containers/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "updated":"2015-05-12T20:08:47.644264",
        "created":"2015-05-12T19:23:44.019168",
        "users":[
          {user_id1},
          {user_id2},
          .....
        ],
        "project-access":{project-access-flag}
      }
    }


Request/Response (With no ACL defined):
***************************************

.. code-block:: javascript

    Request:

    GET /v1/containers/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "project-access": true
      }
    }



HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful request.                                                         |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found for the given UUID.                                     |
+------+-----------------------------------------------------------------------------+

.. _put_container_acl:

PUT /v1/containers/{uuid}/acl
#############################
Create new or replaces existing ACL for a given container.

This call is used to add new ACL for an container. If the ACL is already set on a container,
this method will replace it with the requested ACL settings. In case of create (first new explicit
ACL) or replace existing ACL, 200 is returned in both cases. To delete existing users from
an ACL definition, pass empty list [] for `users`.

Returns an ACL reference in success case.

Attributes
**********

The ACL resource detailed in this page allows access to individual containers to be controlled.
This access is configured via operations on those containers. Currently only the 'read' operation
(which includes GET REST actions) is supported.

+----------------------------+----------+-----------------------------------------------+----------+
| Attribute Name             | Type     | Description                                   | Default  |
+============================+==========+===============================================+==========+
| read                       | parent   | ACL data for read operation.                  | None     |
|                            | element  |                                               |          |
+----------------------------+----------+-----------------------------------------------+----------+
| users                      | [string] | (optional) List of user ids. This needs to be | []       |
|                            |          | a user id as returned by Keystone.            |          |
+----------------------------+----------+-----------------------------------------------+----------+
| project-access             | boolean  | (optional) Flag to mark a container private   | `true`   |
|                            |          | so that the user who created the container and|          |
|                            |          | ``users`` specified in above list can only    |          |
|                            |          | access the container. Pass `false` to mark the|          |
|                            |          | container private.                            |          |
+----------------------------+----------+-----------------------------------------------+----------+

Request/Response (Set or Replace ACL):
**************************************

.. code-block:: javascript

    PUT /v1/containers/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":{
        "users":[
          {user_id1},
          {user_id2},
          .....
        ],
        "project-access":{project-access-flag}
      }
    }

    Response:
    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/containers/{uuid}/acl"}



HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully set/replaced  container ACL.                                   |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found for the given UUID.                                     |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported Media Type.                                                     |
+------+-----------------------------------------------------------------------------+


.. _patch_container_acl:

PATCH /v1/containers/{uuid}/acl
###############################

Update existing ACL for a given container. This method can be used to apply partial changes
on existing ACL settings. Client can update `users` list and enable or disable `project-access`
flag for existing ACL. List of provided users replaces existing users if any. For an existing
list of provided users from an ACL definition, pass empty list [] for `users`.

Returns an ACL reference in success case.

.. note::
    
    PATCH API support will be changing in near future.

Attributes
**********

+----------------------------+----------+-----------------------------------------------+----------+
| Attribute Name             | Type     | Description                                   | Default  |
+============================+==========+===============================================+==========+
| read                       | parent   | ACL data for read operation.                  | None     |
|                            | element  |                                               |          |
+----------------------------+----------+-----------------------------------------------+----------+
| users                      | [string] | (optional) List of user ids. This needs to be | None     |
|                            |          | a user id as returned by Keystone.            |          |
+----------------------------+----------+-----------------------------------------------+----------+
| project-access             | boolean  | (optional) Flag to mark a container private   | None     |
|                            |          | so that the user who created the container and|          |
|                            |          | ``users`` specified in above list can only    |          |
|                            |          | access the container. Pass `false` to mark the|          |
|                            |          | container private.                            |          |
+----------------------------+----------+-----------------------------------------------+----------+

Request/Response (Updating project-access flag):
************************************************

.. code-block:: javascript

    PATCH /v1/containers/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":
        {
          "project-access":false
        }
    }

    Response:
    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/containers/{uuid}/acl"}


Request/Response (Removing all users from ACL):
***********************************************

.. code-block:: javascript

    PATCH /v1/containers/{uuid}/acl
    Headers:
        Content-Type: application/json
        X-Auth-Token: {token_id}

    Body:
    {
      "read":
        {
          "users":[]
        }
    }

    Response:
    HTTP/1.1 200 OK
    {"acl_ref": "https://{barbican_host}/v1/containers/{uuid}/acl"}


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully updated container ACL.                                         |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request.                                                                |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found for the given UUID.                                     |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported Media Type.                                                     |
+------+-----------------------------------------------------------------------------+

.. _delete_container_acl:

DELETE /v1/containers/{uuid}/acl
################################

Delete ACL for a given container. No content is returned in the case of successful
deletion.

Request/Response:
*****************

.. code-block:: javascript

    DELETE /v1/containers/{uuid}/acl
    Headers:
        X-Auth-Token: {token_id}

    Response:
    HTTP/1.1 200 OK


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successfully deleted container ACL.                                         |
+------+-----------------------------------------------------------------------------+
| 401  | Missing or Invalid X-Auth-Token. Authentication required.                   |
+------+-----------------------------------------------------------------------------+
| 403  | User does not have permission to access this resource.                      |
+------+-----------------------------------------------------------------------------+
| 404  | Container not found for the given UUID.                                     |
+------+-----------------------------------------------------------------------------+
