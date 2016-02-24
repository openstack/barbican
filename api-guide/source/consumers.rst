**************************
Consumers API - User Guide
**************************

This guide assumes you will be using a local development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <http://docs.openstack.org/developer/barbican/setup/dev.html>`__.


What is a Consumer?
###################

A consumer is a way to to register as an interested party for a container. All of the registered
consumers can be viewed by performing a GET on the {container_ref}/consumers. The idea
being that before a container is deleted all consumers should be notified of the delete.



.. _create_consumer:

How to Create a Consumer
########################

.. code-block:: bash

     curl -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"name": "consumername", "URL": "consumerURL"}' \
      http://localhost:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9/consumers

This will return the following response:

.. code-block:: json

    {
        "status": "ACTIVE",
        "updated": "2015-10-15T21:06:33.121113",
        "name": "container name",
        "consumers": [
            {
                "URL": "consumerurl",
                "name": "consumername"
            }
        ],
        "created": "2015-10-15T17:55:44.380002",
        "container_ref":
        "http://localhost:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9",
        "creator_id": "b17c815d80f946ea8505c34347a2aeba",
        "secret_refs": [
            {
                "secret_ref": "http://localhost:9311/v1/secrets/b61613fc-be53-4696-ac01-c3a789e87973",
                "name": "private_key"
            }
        ],
        "type": "generic"
    }


.. _retrieve_consumer:

How to Retrieve a Consumer
##########################

To retrieve a consumer perform a GET on the {container_ref}/consumers
This will return all consumers for this container. You can optionally add a
limit and offset query parameter.

.. code-block:: bash

    curl -H "X-Auth-Token: $TOKEN" \
    http://192.168.99.100:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9/consumers

This will return the following response:

.. code-block:: json

    {
        "total": 1,
        "consumers": [
            {
                "status": "ACTIVE",
                "URL": "consumerurl",
                "updated": "2015-10-15T21:06:33.123878",
                "name": "consumername",
                "created": "2015-10-15T21:06:33.123872"
            }
        ]
    }

The returned value is a list of all consumers for the specified container.
Each consumer will be listed with its metadata..

If the offset and limit parameters are specified then you will see a
previous and next reference which allow you to cycle through all of
the consumers for this container.

.. code-block:: bash

    curl -H "X-Auth-Token: $TOKEN" \
    http://192.168.99.100:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9/consumers?limit=1\&offset=1

This will return the following response:

.. code-block:: json

    {
        "total": 3,
        "next": "http://localhost:9311/v1/consumers?limit=1&offset=2",
        "consumers": [
            {
                "status": "ACTIVE",
                "URL": "consumerURL2",
                "updated": "2015-10-15T21:17:08.092416",
                "name": "consumername2",
                "created": "2015-10-15T21:17:08.092408"
            }
        ],
        "previous": "http://localhost:9311/v1/consumers?limit=1&offset=0"
    }

.. _delete_consumer:

How to Delete a Consumer
########################

To delete a consumer for a container you must provide the consumer name and
URL which were used when the consumer was created.

.. code-block:: bash

    curl -X DELETE -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"name": "consumername", "URL": "consumerURL"}' \
      http://localhost:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9/consumers

This will return the following response:

.. code-block:: json

    {
        "status": "ACTIVE",
        "updated": "2015-10-15T17:56:18.626724",
        "name": "container name",
        "consumers": [],
        "created": "2015-10-15T17:55:44.380002",
        "container_ref": "http://localhost:9311/v1/containers/74bbd3fd-9ba8-42ee-b87e-2eecf10e47b9",
        "creator_id": "b17c815d80f946ea8505c34347a2aeba",
        "secret_refs": [
            {
                "secret_ref": "http://localhost:9311/v1/secrets/b61613fc-be53-4696-ac01-c3a789e87973",
                "name": "private_key"
            }
        ],
        "type": "generic"
    }

A successful delete will return an HTTP 200 OK. The response content will be the
container plus the consumer list, minus the consumer which was just deleted.
