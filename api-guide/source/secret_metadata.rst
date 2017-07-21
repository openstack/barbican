********************************
Secret Metadata API - User Guide
********************************

The Secret Metadata resource is an additional resource associated with Secrets.
It allows a user to be able to associate various key/value pairs with a Secret.

.. _create_secret_metadata:

How to Create/Update Secret Metadata
####################################

To create/update the secret metadata for a specific secret, we will need to know
the secret reference of the secret we wish to add user metadata to. Any metadata
that was previously set will be deleted and replaced with this metadata.
For more information on creating/updating secret metadata, you can view the
`PUT /v1/secrets/{uuid}/metadata <https://docs.openstack.org/barbican/latest/api/reference/secret_metadata.html#put-secret-metadata>`__
section.

.. code-block:: bash

    curl -X PUT -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    -d '{ "metadata": {
            "description": "contains the AES key",
            "geolocation": "12.3456, -98.7654"
          }
        }' \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata

This should provide a response as follows:

.. code-block:: bash

    {"metadata_ref": "http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata"}

.. _retrieve_secret_metadata:

How to Retrieve Secret Metadata
###############################

To retrieve the secret metadata for a single key/value pair, we will need to
know the secret reference of the secret we wish to see the user metadata of.
If there is no metadata for a particular secret, then an empty metadata object
will be returned.

.. code-block:: bash

    curl -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata/

This should provide a response as follows:

.. code-block:: bash

    {
        "metadata": {
            "description": "contains the AES key",
            "geolocation": "12.3456, -98.7654"
        }
    }

.. _create_secret_metadatum:

How to Create Individual Secret Metadata
########################################

To create the secret metadata for a single key/value pair, we will need to know
the secret reference. This will create a new key/value pair. In order to update
an already existing key, please see the update section below.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    -d '{ "key": "access-limit", "value": "11" }' \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata

This should provide a response as follows:

.. code-block:: bash

    Secret Metadata Location: http://example.com:9311/v1/secrets/{uuid}/metadata/access-limit
    {
        "key": "access-limit",
        "value": 11
    }

.. _update_secret_metadatum:

How to Update an Individual Secret Metadata
###########################################

To update the secret metadata for a single key/value pair, we will need to know
the secret reference as well as the name of the key.

.. code-block:: bash

    curl -X PUT -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    -d '{ "key": "access-limit", "value": "0" }' \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata/access-limit

This should provide a response as follows:

.. code-block:: bash

    {
        "key": "access-limit",
        "value": 0
    }


.. _retrieve_secret_metadatum:

How to Retrieve an Individual Secret Metadata
#############################################

To retrieve the secret metadata for a specific key/value pair, we will need to
know the secret reference as well as the name of the metadata key.

.. code-block:: bash

    curl -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata/access-limit

This should provide a response as follows:

.. code-block:: bash

    {
        "key": "access-limit",
        "value": 0
    }

.. _remove_secret_metadatum:

How to Delete an Individual Secret Metadata
###########################################

To delete a single secret metadata key/value, we will need to know the secret
reference as well as the name of the metadata key to delete. In order to
delete all metadata for a secret, please see the create/update section at the
top of this page.

.. code-block:: bash

    curl -X DELETE -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/secrets/2a549393-0710-444b-8aa5-84cf0f85ea79/metadata/access-limit

No response will be provided. This is expected behavior! If you do receive a
response, something went wrong and you will have to address that before
moving forward.
