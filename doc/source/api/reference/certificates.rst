****************************
Certificates API - Reference
****************************

.. _reference_post_certificate_orders:

POST /v1/orders
###############
Certificates are requested using the Orders interface.  Detailed description of this interface
is deferred to the Orders API reference.  This reference identifies the parameters that are specific
to each of the certificate order types i.e. those orders for which the parameter *type*
is "certificate".

All orders contain a required parameter *meta*, which is a dictionary containing key-value
parameters which specify the details of an order request.  All the parameters below are passed
in the *meta* dictionary.

The result of this operation is an order for a certificate, returned to the client as an order
reference.  Upon completion, the order will contain a reference to a Certificate Container,
see `Certificate Containers <http://developer.openstack.org/api-guide/key-manager/containers.html#certificate-containers>`__.


Common Attributes
*****************

Certificate orders have the same attributes that are common to all orders.  The table below lists
those parameters that are specific to certificate orders in particular.

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| request_type               | string  | (optional) The type of certificate order     | custom     |
|                            |         | Possible values are stored-key, simple-cmc,  |            |
|                            |         | full-cmc and custom                          |            |
+----------------------------+---------+----------------------------------------------+------------+
| ca_id                      | string  | (optional) The UUID of the CA to which this  | None       |
|                            |         | certificate order should be sent.  This      |            |
|                            |         | UUID can be obtained from the cas interface. |            |
+----------------------------+---------+----------------------------------------------+------------+
| profile                    | string  | (optional) Identifier indicating the         | None       |
|                            |         | certificate product being requested.         |            |
|                            |         | eg. a 3 year server certificate with certain |            |
|                            |         | extensions.  This identifier is CA specific. |            |
|                            |         | Therefore, ca_id is required if the profile  |            |
|                            |         | is provided.                                 |            |
+----------------------------+---------+----------------------------------------------+------------+
| requestor_name             | string  | (optional) Requestor name                    | None       |
+----------------------------+---------+----------------------------------------------+------------+
| requestor_email            | string  | (optional) Requestor email                   | None       |
+----------------------------+---------+----------------------------------------------+------------+
| requestor_phone            | string  | (optional) Requestor phone                   | None       |
+----------------------------+---------+----------------------------------------------+------------+

Attributes for Simple CMC Orders
********************************

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| request_data               | string  | The base64 encoded simple CMC request with   | None       |
|                            |         | no line breaks.   Simple CMC is the same as  |            |
|                            |         | a PKCS10 CSR. (RFC 5272)                     |            |
+----------------------------+---------+----------------------------------------------+------------+

Attributes for Stored Key Requests
**********************************

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| source_container_ref       | string  |  Reference to the RSA container already      | None       |
|                            |         |  stored in Barbican containing the private   |            |
|                            |         |  and public keys.                            |            |
+----------------------------+---------+----------------------------------------------+------------+
| subject_dn                 | string  | Subject DN for the certificate.  This        | None       |
|                            |         | value must comply with RFC 1485.             |            |
+----------------------------+---------+----------------------------------------------+------------+
| extensions                 | string  | (optional) Base 64 DER encoded ASN.1 values  | None       |
|                            |         | for requested certificate extensions,        |            |
|                            |         | Currently, this value is not parsed.         |            |
+----------------------------+---------+----------------------------------------------+------------+

Attributes for Custom Orders
****************************

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| (Varies - depends on CA)   | (Varies)| Custom certificate orders pass arbitrary     | None       |
|                            |         | parameters through the CA unchanged.  It is  |            |
|                            |         | up to the CA to interpret the parameters.    |            |
|                            |         | Note that as the request parameters are CA   |            |
|                            |         | specific, *ca_id* is required for this       |            |
|                            |         | request type.                                |            |
+----------------------------+---------+----------------------------------------------+------------+


Request:
********

The request below shows a simple CMC request.  For examples of each type,
see the `Certificate User's Guide <http://developer.openstack.org/api-guide/key-manager/certificates.html>`.

.. code-block:: javascript

    POST /v1/orders
    Headers:
        Content-Type: application/json
        X-Auth-Token: <token>

    Content:
    {
        "type": "certificate",
        "meta": {
            "request_data": "... base 64 encoded simple CMC ...",
            "request_type": "simple-cmc",
            "ca_id": "422e6ad3-24ae-45e3-b165-4e9487cd0ded",
            "profile": "caServerCert"
         }
    }

Response:
*********

.. code-block:: javascript

    201 Created

    {
        "order_ref": "https://{barbican_host}/v1/orders/{order_uuid}"
    }


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successfully created an Order                                               |
+------+-----------------------------------------------------------------------------+
| 400  | Bad Request                                                                 |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+
| 403  | Forbidden.  The user has been authenticated, but is not authorized to       |
|      | create an order.  This can be based on the the user's role or the project's |
|      | quota.                                                                      |
+------+-----------------------------------------------------------------------------+
| 415  | Unsupported media type                                                      |
+------+-----------------------------------------------------------------------------+

