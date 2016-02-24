******************************
Certificates API - User Guide
******************************

Barbican will be used to manage the lifecycle of x509 certificates covering
operations such as initial certificate issuance, certificate re-issuance,
certificate renewal and certificate revocation.  At present, only the issuance of
certificates is implemented.

This guide will provide some examples on how to use each of the supported operations.
It assumes that you will be using a local running development environment of barbican.
If you need assistance with getting set up, please reference the
`development guide <http://docs.openstack.org/developer/barbican/setup/dev.html>`__.

Barbican can be used to request certificate issuance from a number of private and
public Certificate Authorities (CAs).  This is done through the Orders interface.

There are several types of certificate orders available:
    * :ref:`Simple CMC<simple_cmc_order>`
    * :ref:`Full CMC<full_cmc_order>`
    * :ref:`Stored Key<stored_key_order>`
    * :ref:`Custom<custom_certificate_order>`

An example of each kind of certificate request will be provided below.

When the certificate order is received, a certificate order is generated and the client
will be provided an order reference.  This order will be in PENDING state.  Once the
certificate order has been fulfilled and the certificate is issued, the
order state will be updated to ACTIVE, and the order will be updated to include
a reference to a Certificate Container.

.. _what_is_a_cert_container:

What is a Certificate Container?
################################

A completed certificate order contains a reference to certificate container
as shown below:

.. code-block:: bash

    curl -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/orders/df1d1a0f-8454-46ca-9287-c57ced0418e7

.. code-block:: javascript

    {
        "status": "ACTIVE",
        "sub_status": "cert_generated",
        "updated": "2015-05-09T22:40:05.007512",
        "created": "2015-05-09T22:40:01.556689",
        "container_ref": "http://localhost:9311/v1/containers/1e71dc2b-cf63-4aa4-91f7-41ea1a9e5493",
        "order_ref": "http://localhost:9311/v1/orders/df1d1a0f-8454-46ca-9287-c57ced0418e7",
        "meta": {
            "profile": "caServerCert",
            "request_data": "LS0tLS1CRUdJ...VC0tLS0tCg==",
            "request_type": "simple-cmc",
            "ca_id": "422e6ad3-24ae-45e3-b165-4e9487cd0ded"
         },
        "sub_status_message": "Certificate has been generated",
        "type": "certificate"
    }

Getting the container provides references to secrets for the certificate,
any intermediate certificate chain in PKCS7 format, and potentially references
to the private and any passphrase used to encrypt the private key (if it is stored in
barbican).

.. code-block:: bash

     curl -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/containers/1e71dc2b-cf63-4aa4-91f7-41ea1a9e5493

.. code-block:: javascript

    {
        "status": "ACTIVE",
        "updated": "2015-05-09T22:40:05.003296",
        "name": null,
        "consumers": [],
        "created": "2015-05-09T22:40:05.003296",
        "container_ref": "http://localhost:9311/v1/containers/1e71dc2b-cf63-4aa4-91f7-41ea1a9e5493",
        "creator_id": null,
        "secret_refs": [
            {
                "secret_ref": "http://localhost:9311/v1/secrets/acd47891-9e72-4542-b9de-be66cc343610",
                "name": "certificate"
            },
            {
                "secret_ref": "http://localhost:9311/v1/secrets/a871baa4-6ef2-42db-ba01-13414ab60d9e",
                "name": "intermediates"
            }
        ],
        "type": "certificate"
    }

You can get the certificate itself by extracting the payload of the secret_ref pointed to by the label "certificate".

.. code-block:: bash

    curl -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        -H "Accept:application/pkix-cert" \
        http://localhost:9311/v1/secrets/acd47891-9e72-4542-b9de-be66cc343610/payload

.. code-block:: bash

    -----BEGIN CERTIFICATE-----
    MIIDcTCCAlmgAwIBAgIBWDANBgkqhkiG9w0BAQsFADA/MRwwGgYDVQQKDBNwa2kt
    dG9tY2F0MjYgZG9tYWluMR8wHQYDVQQDDBZDQSBTaWduaW5nIENlcnRpZmljYXRl
    MB4XDTE1MDUwOTIyNDAwMVoXDTE3MDQyODIyNDAwMVowIDEeMBwGA1UEAwwVc2Vy
    ....
    HIG28XVygTC93uQmk1mAUTsIpFsk
    -----END CERTIFICATE-----

.. _finding_the_cas:

What CAs are Available?
#######################

Barbican communicates with public and private CAs through CA plugins that are
configured to communicate with one or more CAs.  CA plugins are configured and
enabled in **barbican.conf**.

To see the list of CA's that are currently configured, you can query the cas
resource:

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas

This should provide a response like the following:

.. code-block:: bash

    {"cas": ["http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581"], "total": 1}

More details on each CA can be obtained by querying the specific CA:

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581

The output shows the status of the CA and the plugin used to communicate with it:

.. code-block:: javascript

    {
        "status": "ACTIVE",
        "updated": "2015-05-09T05:55:37.745132",
        "created": "2015-05-09T05:55:37.745132",
        "plugin_name": "barbican.plugin.dogtag.DogtagCAPlugin",
        "meta": [
            {"name": "Dogtag CA"},
            {"description": "Certificate Authority - Dogtag CA"}
        ],
        "ca_id": "3a2a533d-ed4d-4c68-a418-2ee79f4c9581",
        "plugin_ca_id": "Dogtag CA",
        "expiration": "2015-05-10T05:55:37.740211"
    }

A snake-oil CA plugin is included with the barbican source code for basic testing.
In addition, a robust, enterprise-ready CA plugin is provided for the Dogtag CA.
Instructions for setting up the CA are provided at :doc:`Dogtag Setup Instructions <./dogtag_setup>`.

More details can be found in the
`certificate reference <http://docs.openstack.org/developer/barbican/api/reference/certificates.html>`__.

.. _order_certificate:

How to Order a Certificate
##########################

As mentioned above, several types of certificate orders are available. This
section details each one.

.. _simple_cmc_order:

Simple CMC Certificate Order
****************************

The easiest way to obtain a certificate is to provide a simple CMC request to the
server using a Simple CMC Order type.  In the example below, we will use openssl
commands to generate an RSA key pair and use that key pair to create a CSR.

.. code-block:: bash

    openssl genrsa -out private.pem 2048

    openssl req -new -key private.pem -out csr.pem -subj '/CN=server1,o=example.com'

    base64 ./csr.pem |tr -d '\r\n'

The output of the last command will be a base64 encoded string that can be pasted
into a JSON request for a Simple CMC Certificate order.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" -d '{
         "type": "certificate",
         "meta": {
            "request_data": "LS0tLS1CRUdJT..... oK2Fkh6dXBTVC0tLS0tCg==",
            "request_type": "simple-cmc",
            "ca_id": "422e6ad3-24ae-45e3-b165-4e9487cd0ded",
            "profile": "caServerCert"
         }
    }' http://localhost:9311/v1/orders

The ca_id and profile parameters are not required.  The profile represents a specific
kind of certificate product (a three year server cert, for instance) as defined by the
CA and CA plugin.  For a Dogtag CA, "caServerCert" is usually a profile that corresponds
to a server cert and which is automatically approved and issued.  More details can be
found in :doc:`Dogtag Setup Instructions <./dogtag_setup>`.

The result of this JSON request will be an order reference, which, when fulfilled
will contain a reference to a certificate container.  The certificate can be extracted
as shown above.

.. code-block:: bash

    {"order_ref": "http://localhost:9311/v1/orders/df1d1a0f-8454-46ca-9287-c57ced0418e7"}

.. _full_cmc_order:

Full CMC Certificate Order
**************************

This type has not yet been implemented.

.. _stored_key_order:

Stored Key Certificate Order
****************************

Stored Key certificate orders take advantage of the fact that barbican is also
a repository for secrets.  RSA private keys can be either generated on the client
and stored in barbican beforehand using the secrets interface, or generated in
barbican directly using the orders interface.

All that is required for the certificate order is the reference to the secret container
for the RSA key pair and any parameters needed to generate a CSR.  Barbican will
retrieve the RSA key pair (assuming the user has permission to access it) and will generate
the CSR on the user's behalf.  The CSR will then be submitted to a back-end CA.  This
may be particularly useful for provisioning flows.

In the example below, we will generate a RSA key pair using the Orders interface, and
use this generated secret to create a Stored Key Order.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" -d '{
        "type": "asymmetric",
        "meta": {
            "algorithm": "rsa",
            "bit_length": 2048
        }
    }' http://localhost:9311/v1/orders

This should provide a response as follows:

.. code-block:: bash

    {"order_ref": "http://localhost:9311/v1/orders/cb3c43d6-e30c-40c0-b28c-b0dd58a6209d"}

We can retrieve the reference to the container containing the RSA key pair from the order.

.. code-block:: bash

    curl -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
    http://localhost:9311/v1/orders/cb3c43d6-e30c-40c0-b28c-b0dd58a6209d

.. code-block:: javascript

    {
        "status": "ACTIVE",
        "updated": "2015-05-09T22:40:05.007512",
        "created": "2015-05-09T22:40:01.556689",
        "container_ref": "http://localhost:9311/v1/containers/1e71dc2b-cf63-4aa4-91f7-41ea1a9e5493",
        "order_ref": "http://localhost:9311/v1/orders/cb3c43d6-e30c-40c0-b28c-b0dd58a6209d",
        "meta": {
            "algorithm": "rsa",
            "bit_length": 2048
        },
        "type": "asymmetric"
    }

Now that we have a reference to the container, we can create a stored-key request.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" -d '{
        "type": "certificate",
        "meta": {
            "container_ref": "http://localhost:9311/v1/containers/1e71dc2b-cf63-4aa4-91f7-41ea1a9e5493",
            "subject_dn": "cn=server1, o=example.com",
            "request_type": "stored-key",
            "ca_id": "422e6ad3-24ae-45e3-b165-4e9487cd0ded",
            "profile": "caServerCert"
        }
    }' http://localhost:9311/v1/orders

As noted in the previous section, ca_id and profile are optional.  The response will be a reference to the
created order.


.. _custom_certificate_order:

Custom Certificate Order
########################

A custom certificate order (which is also the order type assumed when no certificate
order type is provided) is an order in which any request attributes are submitted to
the back-end CA unchanged.  This is useful if you wish to communicate with a specific CA
and wish to provide parameters that are specific to that CA.  Because this request
contains parameters that are CA specific, the ca_id is required.

The example below is a custom request for a server cert from a Dogtag CA.  As usual,
the response is an order reference.

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" -d '{
        "type": "certificate",
        "meta": {
            "request_data": "LS0tLS1CRUdJT..... oK2Fkh6dXBTVC0tLS0tCg==",
            "request_type": "custom",
            "ca_id": "422e6ad3-24ae-45e3-b165-4e9487cd0ded",
            "profile": "caServerCert"
        }
    }' http://localhost:9311/v1/orders
