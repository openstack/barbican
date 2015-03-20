***********************
Secrets API - Reference
***********************

GET /secrets
############
Lists a project's secrets.

The list of secrets can be filtered by the parameters passed in via the URL.

Parameters
**********

+--------+---------+----------------------------------------------------------------+
| Name   | Type    | Description                                                    |
+========+=========+================================================================+
| offset | integer | The starting index within the total list of the secrets that   |
|        |         | you would like to retrieve.                                    |
+--------+---------+----------------------------------------------------------------+
| limit  | integer | The maximum number of records to return (up to 100). The       |
|        |         | default limit is 10.                                           |
+--------+---------+----------------------------------------------------------------+
| name   | string  | Selects all secrets with name equal to this value.             |
+--------+---------+----------------------------------------------------------------+
| bits   | integer | Selects all secrets with bit_length equal to this value.       |
+--------+---------+----------------------------------------------------------------+
| alg    | string  | Selects all secrets with algorithm equal to this value.        |
+--------+---------+----------------------------------------------------------------+
| mode   | string  | Selects all secrets with mode equal to this value.             |
+--------+---------+----------------------------------------------------------------+

Response Attributes
*******************

+----------+---------+--------------------------------------------------------------+
| Name     | Type    | Description                                                  |
+==========+=========+==============================================================+
| secrets  | list    | Contains a list of dictionaries filled with secret metadata. |
+----------+---------+--------------------------------------------------------------+
| total    | integer | The total number of secrets available to the user.           |
+----------+---------+--------------------------------------------------------------+
| next     | string  | A HATEOS url to retrieve the next set of secrets based on    |
|          |         | the offset and limit parameters. This attribute is only      |
|          |         | available when the total number of secrets is greater than   |
|          |         | offset and limit parameter combined.                         |
+----------+---------+--------------------------------------------------------------+
| previous | string  | A HATEOS url to retrieve the previous set of secrets based   |
|          |         | on the offset and limit parameters. This attribute is only   |
|          |         | available when the request offset is greater than 0.         |
+----------+---------+--------------------------------------------------------------+


HTTP Status Codes
*****************

+------+-----------------------------------------------------------------------------+
| Code | Description                                                                 |
+======+=============================================================================+
| 200  | Successful Request                                                          |
+------+-----------------------------------------------------------------------------+
| 401  | Invalid X-Auth-Token or the token doesn't have permissions to this resource |
+------+-----------------------------------------------------------------------------+


POST /secrets
#############
Creates a secret

Attributes
**********

+----------------------------+---------+----------------------------------------------+------------+
| Attribute Name             | Type    | Description                                  | Default    |
+============================+=========+==============================================+============+
| name                       | string  | (optional) The name of the secret set by the | None       |
|                            |         | user.                                        |            |
+----------------------------+---------+----------------------------------------------+------------+
| expiration                 | string  | (optional) This is a timestamp in ISO 8601   | None       |
|                            |         | format ``YYYY-MM-DDTHH:MM:SSZ.``             |            |
+----------------------------+---------+----------------------------------------------+------------+
| algorithm                  | string  | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes.           |            |
+----------------------------+---------+----------------------------------------------+------------+
| bit_length                 | integer | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes.           |            |
+----------------------------+---------+----------------------------------------------+------------+
| mode                       | string  | (optional) Metadata provided by a user or    | None       |
|                            |         | system for informational purposes.           |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload                    | string  | (optional) The secret's data to be stored.   | None       |
|                            |         | ``payload_content_type`` must also be        |            |
|                            |         | supplied if payload is provided.             |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload_content_type       | string  | (optional) (required if payload is added)    | None       |
|                            |         | The type and format of the secret data. The  |            |
|                            |         | two supported types are ``text/plain`` and   |            |
|                            |         | ``application/octet-stream``.                |            |
+----------------------------+---------+----------------------------------------------+------------+
| payload_content_encoding   | string  | (optional) The encoding used to format the   | None       |
|                            |         | payload provided. Currently only base64 is   |            |
|                            |         | supported. This is required if content type  |            |
|                            |         | provided has an encoding available.          |            |
+----------------------------+---------+----------------------------------------------+------------+
| secret_type                | string  | (optional) Used to indicate the type of      | ``opaque`` |
|                            |         | secret being stored. If no value is given,   |            |
|                            |         | ``opaque`` is used as the default, which is  |            |
|                            |         | used to signal Barbican to just store the    |            |
|                            |         | information without worrying about format or |            |
|                            |         | encoding.                                    |            |
+----------------------------+---------+----------------------------------------------+------------+

TODO(jvrbanac): Finish this section

GET /secrets/{uuid}
###################
Retrieves a secret's metadata by uuid

TODO(jvrbanac): Finish this section

DELETE /secrets/{uuid}
######################

Delete a secret by uuid

TODO(jvrbanac): Finish this section

GET /secrets/{uuid}/payload
###########################
Retrieve a secret's payload

TODO(jvrbanac): Finish this section

PUT /secrets/{uuid}/payload
###########################
Update a secret's payload

TODO(jvrbanac): Finish this section
