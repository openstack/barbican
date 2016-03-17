************************
Quotas API - User Guide
************************

Running with default settings, the barbican REST API doesn't impose an upper
limit on the number of resources that are allowed to be created. barbican's
backend depends on limited resources. These limited resources include database,
plugin, and Hardware Security Module (HSM) storage space. This
can be an issue in a multi-project or multi-user environment when one project
can exhaust available resources, impacting other projects.

The answer to this, on a per-project basis, is project quotas.

This user guide will show you how a user can lookup his current effective
quotas and how a service admin can create, update, read, and delete project quota
configuration for all projects in his cloud.

This guide will assume you will be using a local running development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <http://docs.openstack.org/developer/barbican/setup/dev.html>`__.

.. _user_project_quotas_overview:

Project Quotas Overview
#######################

All users authenticated with barbican are able to read the effective quota values
that apply to their project.  Barbican can derive the project that a user belongs
to by reading the project scope from the authentication token.

Service administrators can read, set, and delete quota configurations for each
project known to barbican.  The service administrator is recognized by his authenticated
role.  The service administrator's role is defined in barbican's policy.json file.
The default role for a service admin is "key-manager:service-admin".

Quotas can be enforced for the following barbican resources: secrets, containers,
orders, consumers, and CAs.  The configured quota value can be None (use the default),
-1 (unlimited), 0 (disabled), or a positive integer defining the maximum number
allowed for a project.

.. _default_project_quotas:

Default Quotas
--------------

When no project quotas have been set for a project, the default
project quotas are enforced for that project.  Default quotas are specified
in the barbican configuration file (barbican.conf).  The defaults provided
in the standard configuration file are as follows.

.. code-block:: none

    # default number of secrets allowed per project
    quota_secrets = -1

    # default number of orders allowed per project
    quota_orders = -1

    # default number of containers allowed per project
    quota_containers = -1

    # default number of consumers allowed per project
    quota_consumers = -1

    # default number of CAs allowed per project
    quota_cas = -1

The default quotas are returned via a **GET** on the **quotas** resource when no
explicit project quotas have been set for the current project.


.. _user_get_quotas:

How to Read Effective Quotas
############################

The current effective quotas for a project can be read via a **GET** to the **quotas** resource.
Barbican determines the current project ID from the scope of the authentication token sent
with the request.

.. code-block:: bash

    Request:

    curl -i -X GET -H "X-Auth-Token:$TOKEN" \
        -H "Accept:application/json" \
        http://localhost:9311/v1/quotas


    Response:

    HTTP/1.1 200 OK
    Content-Type: application/json; charset=UTF-8
    {"quotas":
        {"secrets": -1,
         "orders": -1,
         "containers": -1,
         "consumers": -1,
         "cas": -1
        }
    }


To get more details on the quota lookup API, you can reference the
`Get Quotas <http://docs.openstack.org/developer/barbican/api/reference/quotas.html#get-quotas-request>`__
documentation.


.. _user_put_project_quotas:

How to Set or Replace Project Quotas
####################################

The quotas for a project can be modified via a **PUT** to the **project-quotas** resource.
This request completely replaces existing quota settings for a project.  The project
ID is passed in the URI of the request.

To set or replace the quotas for the project with the ID 1234:

.. code-block:: bash

    Request:

    curl -i -X PUT -H "content-type:application/json" \
        -H "X-Auth-Token:$TOKEN" \
        -d '{"project_quotas": {"secrets": 500,
        "orders": 100, "containers": -1, "consumers": 100,
        "cas": 50}}' \
        http://localhost:9311/v1/project-quotas/1234

    Response:

    HTTP/1.1 204 No Content


To get more details on the project quota setting API you can reference the
`Set Project Quotas <http://docs.openstack.org/developer/barbican/api/reference/quotas.html#put-project-quotas>`__
documentation.


.. _user_get_project_quotas:

How to Retrieve Configured Project Quotas
#########################################

The project quota information defined for a project can be retrieved by using
a **GET** operation on the respective **project-quota** resource. The project
ID is passed in the URI of the request. The returned response contains project
quota data.

To get project quota information for a single project:

.. code-block:: bash

    Request:

    curl -i -X GET -H "X-Auth-Token:$TOKEN" \
        -H "Accept:application/json" \
        http://localhost:9311/v1/project-quotas/1234

    Response:

    HTTP/1.1 200 OK
    Content-Type: application/json; charset=UTF-8
    {"project_quotas":
        {"secrets": 500,
         "orders": 100,
         "containers": -1,
         "consumers": 100,
         "cas": 50}}


The project quota information defined for all projects can be retrieved by using
a **GET** operation on the **project-quota** resource.
The returned response contains a list with all project quota data.

.. code-block:: bash

    Request:

    curl -i -X GET -H "X-Auth-Token:$TOKEN" \
        -H "Accept:application/json" \
        http://localhost:9311/v1/project-quotas


    Response:

    HTTP/1.1 200 OK
    Content-Type: application/json; charset=UTF-8
    {"project_quotas":
      [{"project_id": "1234",
        "project_quotas":
          {"secrets": 500,
           "orders": 100,
            "containers": -1,
             "consumers": 100,
             "cas": 50}},
       {"project_id": "5678",
        "project_quotas":
          {"secrets": 500,
           "orders": 100,
           "containers": -1,
           "consumers": 100,
           "cas": 50}}]}


To get more details on project quota lookup APIs you can reference
the
`Get Project Quota <http://docs.openstack.org/developer/barbican/api/reference/quotas.html#get-project-quotas-uuid>`__
and
`Get Project Quota List <http://docs.openstack.org/developer/barbican/api/reference/quotas.html#get-project-quotas>`__
documentation.


.. _user_delete_project_quotas:

How to Delete Configured Project Quotas
#######################################

Quotas defined for a project can be deleted by using the **DELETE** operation
on the respective **project-quotas** resource. The quota configuration information
is deleted for a project, the default quotas will then apply to that project.
There is no response content returned on successful deletion.


.. code-block:: bash

    Request:

    curl -i -X DELETE -H "X-Auth-Token:$TOKEN" \
        http://localhost:9311/v1/project-quotas/1234

    Response:

    HTTP/1.1 204 No Content


To get more details on project quota delete APIs, you can reference the
`Delete Project Quotas <http://docs.openstack.org/developer/barbican/api/reference/quotas.html#delete-project-quotas>`__
documentation.
