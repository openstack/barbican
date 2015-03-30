****************************
Containers API - Quick Start
****************************

The containers resource is the organizational center piece of Barbican. It
creates a logical object that can be used to hold secret references. This is helpful
when having to deal with tracking and having access to hundreds of secrets.

Barbican supports 3 types of containers:
  * :ref:`Generic <generic_containers>`
  * :ref:`Certificate <certificate_containers>`
  * :ref:`RSA <rsa_containers>`

Each of these types have explicit restrictions as to what type of secrets should be
held within. These will be broken down in their respective sections.

This guide will assume you will be using a local running development environment of Barbican.
If you need assistance with getting set up, please reference the
:doc:`development guide </setup/dev>`.

.. _generic_containers:

Generic Containers
##################

A generic container is used for any type of container that a user may wish to create.
There are no restrictions on the type or amount of secrets that can be held within a container.

An example of a use case for a generic container would be having multiple passwords stored
in the same container reference:

.. code-block:: json

    {
        "type": "generic",
        "status": "ACTIVE",
        "name": "Test Environment User Passwords",
        "consumers": [],
        "container_ref": "https://{barbican_host}/v1/containers/{uuid}",
        "secret_refs": [
            {
                "name": "test_admin_user",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "test_audit_user",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            }
        ],
        "created": "2015-03-30T21:10:45.417835",
        "updated": "2015-03-30T21:10:45.417835"
    }

For more information on creating a generic container, reference the
:ref:`Creating a Generic Container <create_generic_container>` section.


.. _certificate_containers:

Certificate Containers
######################

.. _rsa_containers:

RSA Containers
##############


.. _create_container:

How to Create a Container
#########################


.. _create_generic_container:

Creating a Generic Container
****************************


.. _create_certificate_container:

Creating a Certificate Container
********************************


.. _create_rsa_container:

Creating an RSA Container
*************************


.. _retrieve_container:

How to Retrieve a Container
###########################


.. _delete_container:

How to Delete a Container
#########################
