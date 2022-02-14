==============
Access Control
==============

Role Based Access Control (RBAC)
--------------------------------

Like many other services, the Key Manager service supports the protection of its
APIs by enforcing policy rules defined in a policy file.  The Key Manager
service stores a reference to a policy JSON file in its configuration file,
:file:`/etc/barbican/barbican.conf`.  Typically this file is named
``policy.yaml`` and it is stored in :file:`/etc/barbican/policy.yaml`.

Each Key Manager API call has a line in the policy file that dictates which
level of access applies:

.. code-block:: ini

    API_NAME: RULE_STATEMENT or MATCH_STATEMENT

where ``RULE_STATEMENT`` can be another ``RULE_STATEMENT`` or a
``MATCH_STATEMENT``:

.. code-block:: ini

   RULE_STATEMENT: RULE_STATEMENT or MATCH_STATEMENT

``MATCH_STATEMENT`` is a set of identifiers that must match between the token
provided by the caller of the API and the parameters or target entities of the
API in question.  For example:

.. code-block:: ini

    "secrets:post": "role:admin or role:creator"

indicates that to create a new secret via a POST request, you must have either
the admin or creator role in your token.

.. warning:: The Key Manager service scopes the ownership of a secret at
    the project level.  This means that many calls in the API will perform an
    additional check to ensure that the project_id of the token matches the
    project_id stored as the secret owner.

Default Policy
~~~~~~~~~~~~~~

The policy engine in OpenStack is very flexible and allows for customized
policies that make sense for your particular cloud.  The Key Manager service
comes with a sample ``policy.yaml`` file which can be used as the starting
point for a customized policy.  The sample policy defines 5 distinct roles:

key-manager:service-admin
    The cloud administrator in charge of the Key Manager service.  This user
    has access to all management APIs like the project-quotas.

admin
    Project administrator.  This user has full access to all resources owned
    by the project for which the admin role is scoped.

creator
    Users with this role are allowed to create new resources and can also
    delete resources which are owned by the project for which the creator role
    is scoped.  They are also allowed full access to existing secrets owned by
    the project in scope.

observer
    Users with this role are allowed to access to existing resources but are
    not allowed to upload new secrets or delete existing secrets.

audit
    Users with this role are only allowed access to the resource metadata.
    So users with this role are unable to decrypt secrets.

Access Control List API
-----------------------

There are some limitations that result from scoping ownership of a secret at the
project level.  For example, it is not possible to grant a user access to a
single secret, as granting a role on a project would allow access to all
all secrets owned by that project.

Additionally, there is no easy way to upload a private secret (i.e. a secret
that only you have access to) without creating a new project for which only
you have roles assigned on it.

To address these limitations the Key Manager service includes an Access Control
List (ACL) API.  For full details see the
`ACL API User Guide <https://docs.openstack.org/api-guide/key-manager/acls.html>`__
