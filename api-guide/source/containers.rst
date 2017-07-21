****************************
Containers API - User Guide
****************************

The containers resource is the organizational center piece of barbican. It
creates a logical object that can be used to hold secret references. This is helpful
when having to deal with tracking and having access to hundreds of secrets.

Barbican supports 3 types of containers:
  * :ref:`Generic <generic_containers>`
  * :ref:`Certificate <certificate_containers>`
  * :ref:`RSA <rsa_containers>`

Each of these types have explicit restrictions as to what type of secrets should be
held within. These will be broken down in their respective sections.

This guide will assume you will be using a local running development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <https://docs.openstack.org/barbican/latest/contributor/dev.html>`__.

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

A certificate container is used for storing the following secrets that are relevant to
certificates:

  * certificate
  * private_key (optional)
  * private_key_passphrase (optional)
  * intermediates (optional)

.. code-block:: json

    {
        "type": "certificate",
        "status": "ACTIVE",
        "name": "Example.com Certificates",
        "consumers": [],
        "container_ref": "https://{barbican_host}/v1/containers/{uuid}",
        "secret_refs": [
            {
                "name": "certificate",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "private_key",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "private_key_passphrase",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "intermediates",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            }

        ],
        "created": "2015-03-30T21:10:45.417835",
        "updated": "2015-03-30T21:10:45.417835"
    }

The payload for the secret referenced as the "certificate" is expected to be a
PEM formatted x509 certificate.

The payload for the secret referenced as the "intermediates" is expected to be a
PEM formatted PKCS7 certificate chain.

For more information on creating a certificate container, reference the
:ref:`Creating a Certificate Container <create_certificate_container>` section.

.. _rsa_containers:

RSA Containers
##############

An RSA container is used for storing RSA public keys, private keys, and private
key pass phrases.

.. code-block:: json

    {
        "type": "rsa",
        "status": "ACTIVE",
        "name": "John Smith RSA",
        "consumers": [],
        "container_ref": "https://{barbican_host}/v1/containers/{uuid}",
        "secret_refs": [
            {
                "name": "private_key",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "private_key_passphrase",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            },
            {
                "name": "public_key",
                "secret_ref": "https://{barbican_host}/v1/secrets/{uuid}"
            }

        ],
        "created": "2015-03-30T21:10:45.417835",
        "updated": "2015-03-30T21:10:45.417835"
    }

For more information on creating a certificate container, reference the
:ref:`Creating a RSA Container <create_certificate_container>` section.

.. _create_container:

How to Create a Container
#########################

In order to create a container, we must first have secrets. If you are unfamiliar
with creating secrets, please take some time to refer to the
:doc:`Secret User Guide <secrets>` before moving forward.

.. _create_generic_container:

Creating a Generic Container
****************************

To create a generic container we must have a secret to store as well.


.. code-block:: bash

    curl -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type:application/json" -d '{
        "type": "generic",
        "name": "generic name",
        "secret_refs": [
            {
                "name": "a secret",
                "secret_ref": "http://localhost:9311/v1/secrets/feac9896-49e9-49e0-9484-1a6153c9498b"
            }
        ]
    }' http://localhost:9311/v1/containers

This should provide a response as follows:

.. code-block:: bash

    {"container_ref": "http://localhost:9311/v1/containers/0fecaec4-7cd7-4e70-a760-cc7eaf5c3afb"}

This is our container reference. We will need this in order to retrieve the container.
Jump ahead to :ref:`How To Retrieve a Container <retrieve_container>` to make sure our
container stored as expected.

.. _create_certificate_container:

Creating a Certificate Container
********************************

To create a certificate container we must have a secret to store as well. As we mentioned
in :ref:`Certificate Containers section <certificate_containers>` you are required
to provide a secret named certificate but may also include the optional secrets
named private_key, private_key_passphrase, and intermediates.


.. code-block:: bash

    curl -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type:application/json" -d '{
        "type": "certificate",
        "name": "certificate container",
        "secret_refs": [
            {
                "name": "certificate",
                "secret_ref": "http://localhost:9311/v1/secrets/f91b84ac-fb19-416b-87dc-e7e41b7f6039"
            },
            {
                "name": "private_key",
                "secret_ref": "http://localhost:9311/v1/secrets/feac9896-49e9-49e0-9484-1a6153c9498b"
            },
            {
                "name": "private_key_passphrase",
                "secret_ref": "http://localhost:9311/v1/secrets/f1106c5b-0347-4197-8947-d9e392bf74a3"
            },
            {
                "name": "intermediates",
                "secret_ref": "http://localhost:9311/v1/secrets/2e86c661-28e8-46f1-8e91-f1d95062695d"
            }
        ]
    }' http://localhost:9311/v1/containers

This should provide a response as follows:

.. code-block:: bash

    {"container_ref": "http://localhost:9311/v1/containers/0fecaec4-7cd7-4e70-a760-cc7eaf5c3afb"}

This is our container reference. We will need this in order to retrieve the container.
Jump ahead to :ref:`How To Retrieve a Container <retrieve_container>` to make sure our
container stored as expected.


.. _create_rsa_container:

Creating an RSA Container
*************************

To create a certificate container we must have a secret to store as well. As we mentioned
in :ref:`RSA Containers section <rsa_containers>` you are required
to provide a secret named public_key, private_key, and private_key_passphrase.


.. code-block:: bash

    curl -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type:application/json" -d '{
        "type": "rsa",
        "name": "rsa container",
        "secret_refs": [
            {
                "name": "public_key",
                "secret_ref": "http://localhost:9311/v1/secrets/f91b84ac-fb19-416b-87dc-e7e41b7f6039"
            },
            {
                "name": "private_key",
                "secret_ref": "http://localhost:9311/v1/secrets/feac9896-49e9-49e0-9484-1a6153c9498b"
            },
            {
                "name": "private_key_passphrase",
                "secret_ref": "http://localhost:9311/v1/secrets/f1106c5b-0347-4197-8947-d9e392bf74a3"
            }
        ]
    }' http://localhost:9311/v1/containers

This should provide a response as follows:

.. code-block:: bash

    {"container_ref": "http://localhost:9311/v1/containers/0fecaec4-7cd7-4e70-a760-cc7eaf5c3afb"}

This is our container reference. We will need this in order to retrieve the container.
Jump ahead to :ref:`How To Retrieve a Container <retrieve_container>` to make sure our
container stored as expected.

.. _retrieve_container:

How to Retrieve a Container
###########################

To retrieve a container we must have a container reference.

.. code-block:: bash

    curl -X GET -H "X-Auth-Token: $TOKEN"  http://localhost:9311/v1/containers/49d3c5e9-80bb-47ec-8787-968bb500d76e

This should provide a response as follows:

.. code-block:: bash

    {
        "status": "ACTIVE",
        "updated": "2015-03-31T21:21:34.126042",
        "name": "container name",
        "consumers": [],
        "created": "2015-03-31T21:21:34.126042",
        "container_ref": "http://localhost:9311/v1/containers/49d3c5e9-80bb-47ec-8787-968bb500d76e",
        "secret_refs": [
            {
                "secret_ref": "http://localhost:9311/v1/secrets/feac9896-49e9-49e0-9484-1a6153c9498b",
                "name": "a secret"
            }
        ],
        "type": "generic"
    }

This is the metadata as well as the list of secret references that are stored within the container.


.. _delete_container:

How to Delete a Container
#########################

To delete a container we must have a container reference.

.. code-block:: bash

    curl -X DELETE -H "X-Auth-Token: $TOKEN" http://localhost:9311/v1/containers/d1c23e06-476b-4684-be9f-8afbef42768d

No response will be provided. This is expected behavior! If you do receive a
response, something went wrong and you will have to address that before
moving forward.
