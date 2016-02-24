******************
ACL API User Guide
******************

By default barbican manages access to its resources (secrets, containers) on a per project
level, whereby a user is allowed access to project resources based on the roles a user has
in that project.

Some barbican use cases prefer a more fine-grained access control for secrets and containers,
such as at the user level. The Access Control List (ACL) feature supports this more restrictive
access.

This guide will assume you will be using a local running development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <http://docs.openstack.org/developer/barbican/setup/dev.html>`__

.. warning::

    This ACL documentation is work in progress and may change in near future.


ACL Definition
##############

ACL defines a set of attributes which are used in policy-based authorization to determine
access to a target resource. ACL definition is operation specific and is defined per
secret or per container.

Currently only the 'read' operation is defined. This supports allowing users on the ACL for a
secret to retrieve its metadata or to decrypt its payload. This also allows users on the ACL
for a container to retrieve its list of secret references.

ACL allow a secret or a container to be marked private. Private secret/container means that only
the user who created the secret/container can extract secret. Users with necessary roles on a
secret/container project will not have access. To allow access to other users, their user ids
need to be added in related ACL users list.

An operation specific ACL definition has following attribute:
  * `users`: Whitelist of users who are allowed access to target resource. In this case a user means
    a Keystone user id.
  * `project-access`: Flag to mark a secret or a container private for an operation. Pass `false` to
    mark private.

To acommplish above mentioned behavior for a secret/container resource, having ACL data populated
alone is not sufficient.

Following ACL rules are defined and used as `OR` in resource access policy:
  * ACL based access is allowed when token user is present in secret/container operation specific
    ACL user list e.g. token user present in `read` users list.
  * When secret/container resource is marked private, then project-level RBAC users access is not
    allowed.

.. note::

    Currently barbican default policy just makes use of `read` ACL data only. So only **GET**
    calls for a secret and a container resource will make use of ACL data. Other request methods on
    secret and container resource still uses project level RBAC checks in policy.

As per default policy rules, a user with `admin` role in a secret/container project or a user who
has created the secret/container can manage ACL for that secret/container.

.. _default_implicit_acl:

Default ACL
-----------

By default when no ACL is explicitly set on a secret or a container, then clients with necessary
roles on secret's project or container's project can access it. This default access pattern translates
to `project-access` as true and no `users` in ACL settings. That's why every secret and container by
default has following implicit ACL.

.. code-block:: json

    {
      "read":{
        "project-access": true
      }
    }


Above default ACL is also returned on **GET** on secret/container **acl** resource when no
explicit ACL is set on it.


.. _set_acl:

How to Set/Replace ACL
######################

The ACL for an existing secret or container can be modified via a **PUT** to the **acl** resource.
This update completely replaces existing ACL settings for this secret or container.


To set/replace an ACL for a secret:

.. code-block:: bash

    Request:

    curl -X PUT -H 'content-type:application/json' \
    -H 'X-Auth-Token:b06183778aa64b17beb6215e60686a60' \
    -d '
    {
      "read":{
        "users":[
          "2d0ee7c681cc4549b6d76769c320d91f",
          "721e27b8505b499e8ab3b38154705b9e",
          "c1d20e4b7e7d4917aee6f0832152269b"
        ],
        "project-access":false
      }
    }' \
    http://localhost:9311/v1/secrets/15621a1b-efdf-41d8-92dc-356cec8e9da9/acl

    Response (includes secret ACL reference):

    HTTP/1.1 201 Created
    {"acl_ref": "http://localhost:9311/v1/secrets/15621a1b-efdf-41d8-92dc-356cec8e9da9/acl"}


To set/replace an ACL for a container:

.. code-block:: bash

    Request:

    curl -X PUT -H 'content-type:application/json' \
    -H 'X-Auth-Token:b06183778aa64b17beb6215e60686a60' \
    -d '
    {
      "read":{
        "users":[
          "2d0ee7c681cc4549b6d76769c320d91f",
          "721e27b8505b499e8ab3b38154705b9e",
          "c1d20e4b7e7d4917aee6f0832152269b"
        ],
        "project-access":false
      }
    }' \
    http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl

    Response (includes container ACL reference):

    HTTP/1.1 201 Created
    {"acl_ref": "http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl"}

To get more details on the create API you can reference the
`Set Secret ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#put-v1-secrets-uuid-acl>`__
or `Set Container ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#put-v1-containers-uuid-acl>`__
documentation.


.. _update_acl:

How to Update ACL
#################

Existing ACL can be updated via **PUT** or **PATCH** methods on a given secret/container.
**PUT** interaction replaces existing ACL with provided ACL data whereas **PATCH**
interaction applies the provided changes on existing ACL of a secret or a container.

To replace an existing ACL for a container:

.. code-block:: bash

    Request:

    curl -X PUT -H 'content-type:application/json' \
    -H 'X-Auth-Token:e1f540bc6def456dbb0f8c11f21a74ae' \
    -d '
    {
      "read":{
        "users":[
          "2d0ee7c681cc4549b6d76769c320d91f",
          "721e27b8505b499e8ab3b38154705b9e"
        ],
        "project-access":true
      }
    }' \
     http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl

    Response (includes container ACL reference):

    HTTP/1.1 200 OK
    {"acl_ref": "http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl"}


To remove all users from an existing ACL for a container (pass empty list in `users`):

.. code-block:: bash

    Request:

    curl -X PUT -H 'content-type:application/json' \
    -H 'X-Auth-Token:e1f540bc6def456dbb0f8c11f21a74ae' \
    -d '
    {
      "read":{
        "users":[],
        "project-access":true
      }
    }' \
     http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl

    Response (includes container ACL reference):

    HTTP/1.1 200 OK
    {"acl_ref": "http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl"}


To update only the `project-access` flag for container ACL (use PATCH):

.. code-block:: bash

    Request:

    curl -X PATCH -H 'content-type:application/json' \
    -H 'X-Auth-Token:e1f540bc6def456dbb0f8c11f21a74ae' \
    -d '
    {
      "read":{
        "project-access":false
      }
    }' \
     http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl

    Response:

    HTTP/1.1 200 OK
    {"acl_ref": "http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl"}


To update only the users list for secret ACL (use PATCH):

.. code-block:: bash

    Request:

    curl -X PATCH -H 'content-type:application/json' \
    -H 'X-Auth-Token:e1f540bc6def456dbb0f8c11f21a74ae' \
    -d '
    {
      "read":{
        "users":[
          "2d0ee7c681cc4549b6d76769c320d91f",
          "c1d20e4b7e7d4917aee6f0832152269b"
        ],
      }
    }' \
     http://localhost:9311/v1/secrets/15621a1b-efdf-41d8-92dc-356cec8e9da9/acl

    Response:

    HTTP/1.1 200 OK
    {"acl_ref": "http://localhost:9311/v1/secrets/15621a1b-efdf-41d8-92dc-356cec8e9da9/acl"}



Container and Secret ACL(s) update operation are similar except `containers` resource is used
instead of the `secrets` resource in URI. To get more details on ACL update APIs, you can reference
the `Update Secret ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#put-secret-acl>`__
, `Update Container ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#put-container-acl>`__
, `Partial Update Secret ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#patch-secret-acl>`__
or `Partial Update Container ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#patch-container-acl>`__
documentation.


.. _retrieve_acl:

How to Retrieve ACL
###################

The ACL defined for a secret or container can be retrieved by using a **GET** operation on
respective **acl** resource.
The returned response contains ACL data.

To get secret ACL data:

.. code-block:: bash

    Request:

    curl -X GET -H 'X-Auth-Token:b44636bff48c41bbb80f459df69c11aa' \
    http://localhost:9311/v1/secrets/15621a1b-efdf-41d8-92dc-356cec8e9da9/acl

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "updated":"2015-05-12T20:08:47.644264",
        "created":"2015-05-12T19:23:44.019168",
        "users":[
          "c1d20e4b7e7d4917aee6f0832152269b",
          "2d0ee7c681cc4549b6d76769c320d91f"
        ],
        "project-access":false
      }
    }


To get container ACL data:

.. code-block:: bash

    Request:

    curl -X GET -H 'X-Auth-Token:b44636bff48c41bbb80f459df69c11aa' \
    http://localhost:9311/v1/containers/8c077991-d524-4e15-8eaf-bc0c3bb225f2/acl

    Response:

    HTTP/1.1 200 OK
    {
      "read":{
        "updated":"2015-05-12T20:05:17.214948",
        "created":"2015-05-12T19:47:20.018657",
        "users":[
          "721e27b8505b499e8ab3b38154705b9e",
          "c1d20e4b7e7d4917aee6f0832152269b",
          "2d0ee7c681cc4549b6d76769c320d91f"
        ],
        "project-access":false
      }
    }


To get more details on ACL lookup APIs you can reference the
`Get Secret ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#get-secret-acl>`__
, `Get Container ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#get-container-acl>`__
documentation.


.. _delete_acl:

How to Delete ACL
#################

ACL defined for a secret or a container can be deleted by using the **DELETE**
operation on their respective `acl` resource. There is no response content
returned on successful deletion.

Delete operation removes existing ACL on a secret or a container if there. It
can be treated as resetting a secret or a container to
`Default ACL <http://docs.openstack.org/developer/barbican/api/userguide/acls.html#default-implicit-acl>`__
setting. That's why invoking delete multiple times on this resource will not
result in error.

.. code-block:: bash

    Request:

    curl -X DELETE -H 'X-Auth-Token:b06183778aa64b17beb6215e60686a60' \
    http://localhost:9311/v1/secrets/50f5ed8e-004e-433a-939c-fa73c7fc81fd/acl

    Response:

    200 OK


To get more details on ACL delete APIs, you can reference the
`Delete Secret ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#delete-secret-acl>`__
, `Delete Container ACL <http://docs.openstack.org/developer/barbican/api/reference/acls.html#delete-container-acl>`__
documentation.
