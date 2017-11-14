*************************
Secrets API - User Guide
*************************

The secrets resource is the heart of the barbican service. It provides access
to the secret / keying material stored in the system.

Barbican supports the storage of data for various content-types securely.

This guide will assume you will be using a local running development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <https://docs.openstack.org/barbican/latest/contributor/dev.html>`__.


What is a Secret?
#################

A secret is a singular item that is stored within barbican. A secret is
anything you want it to be; however, the formal use case is a key that you wish
to store away from prying eyes.

Some examples of a secret may include:
  * Private Key
  * Certificate
  * Password
  * SSH Keys

For the purpose of this user guide, we will use a simple plaintext
secret. If you would like to learn more in detail about
`secret parameters <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#secret-parameters>`__,
`responses <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#secret_response_attributes>`__,
and `status codes <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#secret_status_codes>`__
you can reference the
`secret reference <https://docs.openstack.org/barbican/latest/api/reference/secrets.html>`__
documentation.


.. _create_secret:

How to Create a Secret
######################

Single Step Secret Creation
***************************

The first secret we will create is a single step secret. Using a single step,
barbican expects the user to provide the payload to be stored within the secret
itself. Once the secret has been created with a payload it cannot be updated. In
this example we will provide a plain text secret. For more information on creating
secrets you can view the
`POST /v1/secrets <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#post-secrets>`__
section.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    -d '{"payload": "my-secret-here", "payload_content_type": "text/plain"}' \
    http://localhost:9311/v1/secrets

This should provide a response as follows:

.. code-block:: bash

    {"secret_ref": "http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79"}

This is our secret reference. We will need this in order to retrieve the secret in the following steps.
Jump ahead to :ref:`How to Retrieve a Secret <retrieve_secret>` to make sure our secret is
stored as expected.

.. _two_step_secret_create:

Two Step Secret Creation
************************

The second secret we will create is a two-step secret. A two-step secret will
allow the user to create a secret reference initially, but upload the secret
data after the fact. In this example we will not provide a payload.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    -d '{}' http://localhost:9311/v1/secrets

This should provide a response as follows:

.. code-block:: bash

    {"secret_ref": "http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79"}

Now that we have a secret reference available, we can update the secret data.

.. _update_secret:

How to Update a Secret
######################

To update the secret data we will need to know the secret reference provided
via the initial creation. (See :ref:`Two Step Secret Creation <two_step_secret_create>`
for more information.) In the example below, the secret ref is used from the
previous example. You will have to substitute the uuid after /secrets/ with
your own in order to update the secret.

.. code-block:: bash

    curl -X PUT -H "content-type:text/plain" -H "X-Auth-Token: $TOKEN" \
    -d 'my-secret-here' \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79

No response will be provided. This is expected behavior! If you do receive a
response, something went wrong and you will have to address that before
moving forward. (For more information visit
`PUT /v1/secrets/{uuid} <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#put-secrets>`__
.)


.. _retrieve_secret:

How to Retrieve a Secret
########################

To retrieve the secret we have created we will need to know the secret reference
provided via the initial creation (See :ref:`How to Create a Secret <create_secret>`.)

.. code-block:: bash

    curl -H "Accept: text/plain" -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/payload

This should provide a response as follows:

.. code-block:: bash

    my-secret-here

This is the plain text data we provided upon initial creation of the secret.

How to Delete a Secret
######################

To delete a secret we will need to know the secret reference provided via
the initial creation (See :ref:`How to Create a Secret <create_secret>`.)

.. code-block:: bash

    curl -X DELETE -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79

No response will be provided. This is expected behavior! If you do receive a
response, something went wrong and you will have to address that before
moving forward. (For more information visit
`DELETE /v1/secrets/{uuid} <https://docs.openstack.org/barbican/latest/api/reference/secrets.html#delete-secrets>`__
.)
