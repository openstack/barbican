****************************************
Certificates Authorities API - Reference
****************************************

Barbican provides an API to interact with certificate authorities (CAs).  For
an introduction to CAs and how Barbican manages them, see the
`Certificate Authorities User's Guide <http://developer.openstack.org/api-guide/key-manager/cas.html>`__.

Understanding the following concepts, explained in the user's
guide, is important to understanding how to use this API.

- Certificate Authorities
- Subordinate Certificate Authorities
- Project CAs
- Preferred CAs
- Global Preferred CAs

This document will focus on the details of the Barbican /v1/cas REST API.

GET /v1/cas
###########
Any user can request a list of CAs that may be used.  Depending on the settings
for the user's project, the returned list may be filtered.
If a project has project CAs configured, the list will only contain only the
project CAs and the subordinate CAs for that project.  If not, it will contain
all of the configured CAs and none of the subordinate CAs owned by other
projects.

.. _get_cas_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"cas": ["http://localhost:9311/v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54",
                   "http://localhost:9311/v1/cas/d9e853eb-aea4-4002-9be7-78665062f393"],
           "total": 2}


.. _get_cas_parameters:

Parameters
**********

+--------------+---------+----------------------------------------------------------------+
| Name         | Type    | Description                                                    |
+==============+=========+================================================================+
| offset       | integer | The starting index within the total list of the project        |
|              |         | CAs that you would like to receive.                            |
+--------------+---------+----------------------------------------------------------------+
| limit        | integer | The maximum number of records to return.                       |
+--------------+---------+----------------------------------------------------------------+
| plugin_name  | string  | Filter the returned list of CAs based on plugin name           |
+--------------+---------+----------------------------------------------------------------+
| plugin_id    | string  | Filter the returned list of CAs based on plugin id             |
+--------------+---------+----------------------------------------------------------------+

.. _get_cas_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| cas            | list    | A list of CA references                                      |
+----------------+---------+--------------------------------------------------------------+
| total          | integer | The total number of configured project CAs records.          |
+----------------+---------+--------------------------------------------------------------+
| next           | string  | A HATEOAS url to retrieve the next set of CAs based on       |
|                |         | the offset and limit parameters. This attribute is only      |
|                |         | available when the total number of secrets is greater than   |
|                |         | offset and limit parameter combined.                         |
+----------------+---------+--------------------------------------------------------------+
| previous       | string  | A HATEOAS url to retrieve the previous set of CAs based      |
|                |         | on the offset and limit parameters. This attribute is only   |
|                |         | available when the request offset is greater than 0.         |
+----------------+---------+--------------------------------------------------------------+

.. _get_cas_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+


GET /v1/cas/all
###############
A project admin can request a list of CAs that may be used.  This returned list will
include root certificates, as well as CAs assigned to the project and subCAs
created for this project.  This will allow a project admin to find all CAs that
his project could have access to, so he can manage his project CA list.

.. _get_cas_all_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/all
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"cas": ["http://localhost:9311/v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54",
                   "http://localhost:9311/v1/cas/d9e853eb-aea4-4002-9be7-78665062f393"],
           "total": 2}


.. _get_cas_all_parameters:

Parameters
**********

+--------------+---------+----------------------------------------------------------------+
| Name         | Type    | Description                                                    |
+==============+=========+================================================================+
| offset       | integer | The starting index within the total list of the project        |
|              |         | CAs that you would like to receive.                            |
+--------------+---------+----------------------------------------------------------------+
| limit        | integer | The maximum number of records to return.                       |
+--------------+---------+----------------------------------------------------------------+
| plugin_name  | string  | Filter the returned list of CAs based on plugin name           |
+--------------+---------+----------------------------------------------------------------+
| plugin_id    | string  | Filter the returned list of CAs based on plugin id             |
+--------------+---------+----------------------------------------------------------------+

.. _get_cas_all_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| cas            | list    | A list of CA references                                      |
+----------------+---------+--------------------------------------------------------------+
| total          | integer | The total number of configured project CAs records.          |
+----------------+---------+--------------------------------------------------------------+
| next           | string  | A HATEOAS url to retrieve the next set of CAs based on       |
|                |         | the offset and limit parameters. This attribute is only      |
|                |         | available when the total number of secrets is greater than   |
|                |         | offset and limit parameter combined.                         |
+----------------+---------+--------------------------------------------------------------+
| previous       | string  | A HATEOAS url to retrieve the previous set of CAs based      |
|                |         | on the offset and limit parameters. This attribute is only   |
|                |         | available when the request offset is greater than 0.         |
+----------------+---------+--------------------------------------------------------------+

.. _get_cas_all_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/{CA_ID}
###################
Any user can request details about a CA to which he has permissions.

.. _get_cas_caid_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"status": "ACTIVE",
            "updated": "2015-09-22T05:25:35.305647",
            "created": "2015-09-22T05:25:35.305647",
            "plugin_name": "barbican.plugin.snakeoil_ca.SnakeoilCACertificatePlugin",
            "meta": [{"ca_signing_certificate": "-----BEGIN CERTIFICATE-----
                        MIIC+zCCAeOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MR0wGwYDVQQDDBRTbmFr
                        ZW9pbCBDZXJ0aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcNMTUwOTI0
                        MDM0MTI4WhcNMTUwOTI0MDQ0MjE4WjA1MR0wGwYDVQQDDBRTbmFrZW9pbCBDZXJ0
                        aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
                        A4IBDwAwggEKAoIBAQC2OonnytCeizC+2FJlS7rUOjrIukKndwltXex46YUem09T
                        y2+5ZNvl1QypUN1JXZSjUT27oG9jUTsNUzLHuJe8dW6p3z37WNpBCJY5BOjoDFG9
                        ce5ZrzucVs6QDnsuqD9NqtiECVFNg1qQjVvg9n5I0pl81c0mEfjWwqgOJ303W0IY
                        KnisMByXewyPN57cZuTJQFhUT3fvxF5W1MM03fqILKELL0WE9ALeTThHR9fJRras
                        QgrJYNnb20RwUZv5hqP21iwsaq3CV2+KODR4IlgglFXRN4gfIzZ9cfst95yy0nhV
                        pcf6+IOycYZP7enTEU4e1jtfNn40yQPLlKei9/jrAgMBAAGjFjAUMBIGA1UdEwEB
                        /wQIMAYBAf8CAQUwDQYJKoZIhvcNAQELBQADggEBAEn0wkHsMN7vvDShFLKlpE+1
                        twrIqSekgqb5wdAId9sKblXQTojI6caiImCleFVzhKxQvuoS31dpg7hh2zw+I8P1
                        U0zvYrJlM8HVunHkWIdFuEuP7hrDnTA2NZbEN7EBSDksNtC+T+hcZcYcIs3hpV7p
                        PdjhjU9D4IcFd7ooVra7Lt2q3zl2XZ7TCzkIWV9jqCBNrlf7Q6QkLWe41k6kIJUT
                        bl0HHqk9cRxr9hkwMKTjIO6G6gbPepqOuyEym8qjyVckRCQN8W+HUI3FV/XBcDk5
                        FkhWnqzJ6aTjBQD3WxOtnhm421dERi60RHdTInK6l6BKRUstmPyc3nfMouBarH8=
                        -----END CERTIFICATE-----
                        "}},
                        {"intermediates": "-----BEGIN PKCS7-----
                        MIIDLAYJKoZIhvcNAQcCoIIDHTCCAxkCAQExADALBgkqhkiG9w0BBwGgggL/MIIC
                        +zCCAeOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MR0wGwYDVQQDDBRTbmFrZW9p
                        bCBDZXJ0aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcNMTUwOTI0MDM0
                        MTI4WhcNMTUwOTI0MDQ0MjE4WjA1MR0wGwYDVQQDDBRTbmFrZW9pbCBDZXJ0aWZp
                        Y2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
                        DwAwggEKAoIBAQC2OonnytCeizC+2FJlS7rUOjrIukKndwltXex46YUem09Ty2+5
                        ZNvl1QypUN1JXZSjUT27oG9jUTsNUzLHuJe8dW6p3z37WNpBCJY5BOjoDFG9ce5Z
                        rzucVs6QDnsuqD9NqtiECVFNg1qQjVvg9n5I0pl81c0mEfjWwqgOJ303W0IYKnis
                        MByXewyPN57cZuTJQFhUT3fvxF5W1MM03fqILKELL0WE9ALeTThHR9fJRrasQgrJ
                        YNnb20RwUZv5hqP21iwsaq3CV2+KODR4IlgglFXRN4gfIzZ9cfst95yy0nhVpcf6
                        +IOycYZP7enTEU4e1jtfNn40yQPLlKei9/jrAgMBAAGjFjAUMBIGA1UdEwEB/wQI
                        MAYBAf8CAQUwDQYJKoZIhvcNAQELBQADggEBAEn0wkHsMN7vvDShFLKlpE+1twrI
                        qSekgqb5wdAId9sKblXQTojI6caiImCleFVzhKxQvuoS31dpg7hh2zw+I8P1U0zv
                        YrJlM8HVunHkWIdFuEuP7hrDnTA2NZbEN7EBSDksNtC+T+hcZcYcIs3hpV7pPdjh
                        jU9D4IcFd7ooVra7Lt2q3zl2XZ7TCzkIWV9jqCBNrlf7Q6QkLWe41k6kIJUTbl0H
                        Hqk9cRxr9hkwMKTjIO6G6gbPepqOuyEym8qjyVckRCQN8W+HUI3FV/XBcDk5FkhW
                        nqzJ6aTjBQD3WxOtnhm421dERi60RHdTInK6l6BKRUstmPyc3nfMouBarH+hADEA
                        -----END PKCS7-----
                        "},
                     {"description": "Certificate Authority - Snakeoil CA"},
                     {"name": "Snakeoil CA"}],
            "ca_id": "9277c4b4-2c7a-4612-a693-1e738a83eb54",
            "plugin_ca_id": "Snakeoil CA",
            "expiration": "2015-09-23T05:25:35.300633"}


.. _get_cas_caid_response_attributes:

Response Attributes
*******************

+------------------------+---------+--------------------------------------------------------------+
| Name                   | Type    | Description                                                  |
+========================+=========+==============================================================+
| status                 | list    | Status of the CA                                             |
+------------------------+---------+--------------------------------------------------------------+
| updated                | time    | Date and time CA was last updated                    .       |
+------------------------+---------+--------------------------------------------------------------+
| created                | time    | Date and time CA was created                                 |
+------------------------+---------+--------------------------------------------------------------+
| plugin_name            | string  | Name of certificate plugin associated with this CA           |
+------------------------+---------+--------------------------------------------------------------+
| meta                   | list    | List of additional information for this CA                   |
+------------------------+---------+--------------------------------------------------------------+
| ca_signing_certificate | PEM     | Part of meta, the CA signing certificate for this CA         |
+------------------------+---------+--------------------------------------------------------------+
| intermediates          | pkcs7   | Part of meta, the intermediate certificate chain for this CA |
+------------------------+---------+--------------------------------------------------------------+
| description            | string  | Part of meta, a description given to the CA                  |
+------------------------+---------+--------------------------------------------------------------+
| name                   | string  | Part of meta, a given name for a CA                          |
+------------------------+---------+--------------------------------------------------------------+
| ca_id                  | string  | ID of this CA                                                |
+------------------------+---------+--------------------------------------------------------------+
| plugin_ca_id           | string  | ID of the plugin                                             |
+------------------------+---------+--------------------------------------------------------------+
| expiration             | time    | Expiration date of the CA                                    |
+------------------------+---------+--------------------------------------------------------------+

.. _get_cas_caid_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/{CA_ID}/cacert
##########################
Any user can request the CA signing certificate of a CA to which he has permissions.  The
format of the returned certificate will be PEM.

.. _get_cas_caid_cacert_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/cacert
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 200 OK
          Content-Type: text/html

          -----BEGIN CERTIFICATE-----
          MIIC+zCCAeOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MR0wGwYDVQQDDBRTbmFr
          ZW9pbCBDZXJ0aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcNMTUwOTI0
          MDM0MTI4WhcNMTUwOTI0MDQ0MjE4WjA1MR0wGwYDVQQDDBRTbmFrZW9pbCBDZXJ0
          aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
          A4IBDwAwggEKAoIBAQC2OonnytCeizC+2FJlS7rUOjrIukKndwltXex46YUem09T
          y2+5ZNvl1QypUN1JXZSjUT27oG9jUTsNUzLHuJe8dW6p3z37WNpBCJY5BOjoDFG9
          ce5ZrzucVs6QDnsuqD9NqtiECVFNg1qQjVvg9n5I0pl81c0mEfjWwqgOJ303W0IY
          KnisMByXewyPN57cZuTJQFhUT3fvxF5W1MM03fqILKELL0WE9ALeTThHR9fJRras
          QgrJYNnb20RwUZv5hqP21iwsaq3CV2+KODR4IlgglFXRN4gfIzZ9cfst95yy0nhV
          pcf6+IOycYZP7enTEU4e1jtfNn40yQPLlKei9/jrAgMBAAGjFjAUMBIGA1UdEwEB
          /wQIMAYBAf8CAQUwDQYJKoZIhvcNAQELBQADggEBAEn0wkHsMN7vvDShFLKlpE+1
          twrIqSekgqb5wdAId9sKblXQTojI6caiImCleFVzhKxQvuoS31dpg7hh2zw+I8P1
          U0zvYrJlM8HVunHkWIdFuEuP7hrDnTA2NZbEN7EBSDksNtC+T+hcZcYcIs3hpV7p
          PdjhjU9D4IcFd7ooVra7Lt2q3zl2XZ7TCzkIWV9jqCBNrlf7Q6QkLWe41k6kIJUT
          bl0HHqk9cRxr9hkwMKTjIO6G6gbPepqOuyEym8qjyVckRCQN8W+HUI3FV/XBcDk5
          FkhWnqzJ6aTjBQD3WxOtnhm421dERi60RHdTInK6l6BKRUstmPyc3nfMouBarH8=
          -----END CERTIFICATE-----

.. _get_cas_caid_cacert_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/{CA_ID}/intermediates
#################################
Any user can request the certificate chain of a CA to which he has permissions.
The format of the returned chain will be PKCS#7.

.. _get_cas_caid_intermediates_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/intermediates
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 200 OK
          Content-Type: text/html

          -----BEGIN PKCS7-----
          MIIDLAYJKoZIhvcNAQcCoIIDHTCCAxkCAQExADALBgkqhkiG9w0BBwGgggL/MIIC
          +zCCAeOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MR0wGwYDVQQDDBRTbmFrZW9p
          bCBDZXJ0aWZpY2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcNMTUwOTI0MDM0
          MTI4WhcNMTUwOTI0MDQ0MjE4WjA1MR0wGwYDVQQDDBRTbmFrZW9pbCBDZXJ0aWZp
          Y2F0ZTEUMBIGA1UECgwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
          DwAwggEKAoIBAQC2OonnytCeizC+2FJlS7rUOjrIukKndwltXex46YUem09Ty2+5
          ZNvl1QypUN1JXZSjUT27oG9jUTsNUzLHuJe8dW6p3z37WNpBCJY5BOjoDFG9ce5Z
          rzucVs6QDnsuqD9NqtiECVFNg1qQjVvg9n5I0pl81c0mEfjWwqgOJ303W0IYKnis
          MByXewyPN57cZuTJQFhUT3fvxF5W1MM03fqILKELL0WE9ALeTThHR9fJRrasQgrJ
          YNnb20RwUZv5hqP21iwsaq3CV2+KODR4IlgglFXRN4gfIzZ9cfst95yy0nhVpcf6
          +IOycYZP7enTEU4e1jtfNn40yQPLlKei9/jrAgMBAAGjFjAUMBIGA1UdEwEB/wQI
          MAYBAf8CAQUwDQYJKoZIhvcNAQELBQADggEBAEn0wkHsMN7vvDShFLKlpE+1twrI
          qSekgqb5wdAId9sKblXQTojI6caiImCleFVzhKxQvuoS31dpg7hh2zw+I8P1U0zv
          YrJlM8HVunHkWIdFuEuP7hrDnTA2NZbEN7EBSDksNtC+T+hcZcYcIs3hpV7pPdjh
          jU9D4IcFd7ooVra7Lt2q3zl2XZ7TCzkIWV9jqCBNrlf7Q6QkLWe41k6kIJUTbl0H
          Hqk9cRxr9hkwMKTjIO6G6gbPepqOuyEym8qjyVckRCQN8W+HUI3FV/XBcDk5FkhW
          nqzJ6aTjBQD3WxOtnhm421dERi60RHdTInK6l6BKRUstmPyc3nfMouBarH+hADEA
          -----END PKCS7-----

.. _get_cas_caid_intermediates_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+

POST /v1/cas
############
A project admin can request to create a new subordinate CA for his project.

.. _post_cas_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas
          Headers:
            X-Auth-Token:<token>
            Content-type: application/json
            Accept: application/json

         {"name": "Subordinate CA",
          "description": "Test Snake Oil Subordinate CA",
          "parent_ca_ref": "http://localhost:9311/v1/cas/d9e853eb-aea4-4002-9be7-78665062f393",
          "subject_dn": "CN=Subordinate CA, O=example.com"}

        Response:

          HTTP/1.1 201 OK
          Content-Type: application/json

          {"ca_ref": "http://localhost:9311/v1/cas/a031dcf4-2e2a-4df1-8651-3b424eb6174e"}


.. _post_cas_request_attributes:

Request Attributes
******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| name           | string  | A name that can be used to reference this subCA              |
+----------------+---------+--------------------------------------------------------------+
| description    | string  | A description to be stored with this subCA           .       |
+----------------+---------+--------------------------------------------------------------+
| parent_ca_ref  | string  | A URI referencing the parent CA to be used to issue the      |
|                |         | subordinate CA's signing certificate                         |
+----------------+---------+--------------------------------------------------------------+
| subject_dn     | string  | The subject distinguished name corresponding to this subCA   |
+----------------+---------+--------------------------------------------------------------+

.. _post_cas_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| ca_ref         | string  | A URL that references the created subCA                      |
+----------------+---------+--------------------------------------------------------------+

.. _post_cas_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 201  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad request.  The content or format of the request is wrong.                |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+

DELETE /v1/cas/{CA_ID}
######################
A project administrator can delete a subCA that has been created for his project.  Root
CAs that are defined in the barbican.conf configuration file can not be deleted.  If
there is more than one project CA, the preferred CA can not be deleted until another
project CA has been selected as preferred.

.. _delete_cas_caid_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          DELETE /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 204 OK


.. _delete_cas_caid_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action.   |
|      | This error can occur if a request is made to delete a root CA.              |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+
| 409  | The requested CA can not be delete because it is currently set as the       |
|      | project preferred CA.                                                       |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/preferred
#####################
Any user can request a reference to the preferred CA assigned to his project.  When
a preferred CA is set for a project, that is the CA that will be used when a user
of that project requests a certificate and does not specify a CA.  For more
information, consult the
`Certificate Authorities User's Guide <http://developer.openstack.org/api-guide/key-manager/cas.html>`__
and the
`Certificates API User's Guide <http://developer.openstack.org/api-guide/key-manager/certificates.html>`__.

.. _get_cas_preferred_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/preferred
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"ca_ref": "http://localhost:9311/v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54"}


.. _get_cas_preferred_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| ca_ref         | string  | A URL that references the preferred CA                       |
+----------------+---------+--------------------------------------------------------------+

.. _get_cas_preferred_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | Not found.  No preferred CA has been defined.                               |
+------+-----------------------------------------------------------------------------+

POST /v1/cas/{CA_ID}/add-to-project
###################################
A project administrator can add a CA to his project list.  The CA must be a
root CA or a subCA created by that project.  When a project administrator
adds a CA to the project list, he limits the number of CA that project users
can use; they will only be able to use CAs that are project CAs or subCAs
of the project.  The first created project CA becomes the project's preferred
CA by default.

For more information, consult the
`Certificate Authorities User's Guide <http://developer.openstack.org/api-guide/key-manager/cas.html>`__
and the
`Certificates API User's Guide <http://developer.openstack.org/api-guide/key-manager/certificates.html>`__.

.. _post_cas_caid_add_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/add-to-project
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 204 OK


.. _post_cas_caid_add_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+


POST /v1/cas/{CA_ID}/remove-from-project
########################################
A project administrator can remove a CA from his project list.  If a project
CA requested for removal is also the preferred CA for the project, and there
are other project CAs, then this command will fail. The project administrator
must first set a new preferred CA before deleting this CA.

.. _post_cas_caid_remove_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/remove-from-project
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 204 OK


.. _post_cas_caid_remove_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action.   |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found or not part of the project's CA          |
|      | list                                                                        |
+------+-----------------------------------------------------------------------------+
| 409  | Conflict.  The remove action was blocked because the requested              |
|      | CA is set as the project preferred CA.  The user must set another CA        |
|      | to be the preferred CA to remedy this error.                                |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/{CA_ID}/projects
############################
A service administrator can request a list of project who have the specified CA as
part of their project CA list.

.. _get_cas_caid_projects_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/projects
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"projects": ["4d2f8335-2af8-4a88-851f-2e745bd4860c"]}


.. _get_cas_caid_projects_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| projects       | list    | A list of project IDs associated with the CA                 |
+----------------+---------+--------------------------------------------------------------+

.. _get_cas_caid_projects_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+

POST /v1/cas/{CA_ID}/set-preferred
##################################
A project administrator can set a CA to be the preferred CA for his project.  A
preferred CA must first be assigned as a project CA. There can only be one
preferred CA for a project.  Setting a CA as preferred, also removes the
preferred setting from any other project CA.

.. _post_cas_caid_set_pref_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/set-preferred
          Headers:
            X-Auth-Token:<token>

        Response:

          HTTP/1.1 204 OK


.. _post_cas_caid_set_pref_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad request.  The requested CA is not valid to be a preferred CA for this   |
|      | project                                                                     |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+

GET /v1/cas/global-preferred
############################
A service administrator can can request a reference to the CA that has been assigned
to be the global preferred CA.

.. _get_cas_global_preferred_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          GET /v1/cas/global-preferred
          Headers:
            X-Auth-Token:<token>
            Accept: application/json


        Response:

          HTTP/1.1 200 OK
          Content-Type: application/json

          {"ca_ref": "http://localhost:9311/v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54"}


.. _get_cas_global_preferred_response_attributes:

Response Attributes
*******************

+----------------+---------+--------------------------------------------------------------+
| Name           | Type    | Description                                                  |
+================+=========+==============================================================+
| ca_ref         | string  | A URL that references the global preferred CA                |
+----------------+---------+--------------------------------------------------------------+

.. _get_cas_global_preferred_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | Not found.  No global preferred CA has been defined.                        |
+------+-----------------------------------------------------------------------------+

POST /v1/cas/{CA_ID}/set-global-preferred
#########################################
A service administrator can set the global preferred CA value.  When
a global preferred CA is set, that is the CA that will be used when a user
requests a certificate and does not specify a CA and his project does not
have a project preferred CA.

For more information, consult the
`Certificate Authorities User's Guide <http://developer.openstack.org/api-guide/key-manager/cas.html>`__
and the
`Certificates API User's Guide <http://developer.openstack.org/api-guide/key-manager/certificates.html>`__.

.. _post_cas_caid_set_global_pref_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/set-global-preferred
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 204 OK


.. _post_cas_caid_set_global_pref_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 400  | Bad request.  The requested CA is not valid to be a global preferred CA     |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+

POST /v1/cas/unset-global-preferred
###################################
A service administrator can remove the setting of global preferred CA.

.. _post_cas_caid_unset_global_pref_request_response:

Request/Response:
*****************

.. code-block:: javascript

        Request:

          POST /v1/cas/9277c4b4-2c7a-4612-a693-1e738a83eb54/unset-global-preferred
          Headers:
            X-Auth-Token:<token>
            Accept: */*


        Response:

          HTTP/1.1 204 OK


.. _post_cas_caid_unset_global_pref_status_codes:

HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 204  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Authentication error.  Missing or invalid X-Auth-Token.                     |
+------+-----------------------------------------------------------------------------+
| 403  | The user was authenticated, but is not authorized to perform this action    |
+------+-----------------------------------------------------------------------------+
| 404  | The requested entity was not found                                          |
+------+-----------------------------------------------------------------------------+
