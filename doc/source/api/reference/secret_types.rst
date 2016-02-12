************************
Secret Types - Reference
************************

Every Secret in Barbican has a type.  Secret types are used to describe
different kinds of secret data that are stored in Barbican.  The type for a
particular secret is listed in the secret's metadata as the ``secret_type``
attribute.

The possible secret types are:

* ``symmetric`` - Used for storing byte arrays such as keys suitable for
  symmetric encryption.
* ``public`` - Used for storing the public key of an asymmetric keypair.
* ``private`` - Used for storing the private key of an asymmetric keypair.
* ``passphrase`` - Used for storing plain text passphrases.
* ``certificate`` - Used for storing cryptographic certificates such as X.509
  certificates.
* ``opaque`` - Used for backwards compatibility with previous versions of the
  API without typed secrets.  New applications are encouraged to specify one
  of the other secret types.

Symmetric Keys
##############

The ``symmetric`` secret type is used to store byte arrays of sensitive data,
such as keys that are used for symmetric encryption.  The content type used
with symmetric keys is ``application/octet-stream``.  When storing a symmetric
secret with a single POST request, the data must be encoded so that it may
be included inside the JSON body of the request.  In this case, the
content encoding of ``base64`` can be used.

Example
*******

Create an encryption key for use in AES-256-CBC encryption and store it in
Barbican.  First, we'll see how this can be done in a single POST request from
the command line using curl.

.. code-block:: bash

   # Create an encryption_key file with 256 bits of random data
   dd bs=32 count=1 if=/dev/urandom of=encryption_key

   # Encode the contents of the encryption key using base64 encoding
   KEY_BASE64=$(base64 < encryption_key)

   # Send a request to store the key in Barbican
   curl -vv -H "X-Auth-Token: $TOKEN" -H 'Accept: application/json' \
   -H 'Content-Type: application/json' \
   -d '{"name": "AES encryption key",
        "secret_type": "symmetric",
        "payload": "'"$KEY_BASE64"'",
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64",
        "algorithm": "AES",
        "bit_length": 256,
        "mode": "CBC"}' \
   http://localhost:9311/v1/secrets | python -m json.tool

This should return a reference (URI) for the Secret that was created:

.. code-block:: json

   {
     "secret_ref": "http://localhost:9311/v1/secrets/48d24158-b4b4-45b8-9669-d9f0ef793c23"
   }

We can use this reference to retrieve the secret metadata:

.. code-block:: bash

   curl -vv -H "X-Auth-Token: $TOKEN" -H 'Accept: application/json' \
   http://localhost:9311/v1/secrets/48d24158-b4b4-45b8-9669-d9f0ef793c23 |
   python -m json.tool

The metadata will list the available content types for the symmetric secret:

.. code-block:: json

    {
        "algorithm": "AES",
        "bit_length": 256,
        "content_types": {
            "default": "application/octet-stream"
        },
        "created": "2015-04-08T06:24:16.600393",
        "creator_id": "3a7e3d2421384f56a8fb6cf082a8efab",
        "expiration": null,
        "mode": "CBC",
        "name": "AES encryption key",
        "secret_ref": "http://localhost:9311/v1/secrets/48d24158-b4b4-45b8-9669-d9f0ef793c23",
        "secret_type": "symmetric",
        "status": "ACTIVE",
        "updated": "2015-04-08T06:24:16.614204"
    }

The ``content_types`` attribute describes the content types that can be used
to retrieve the payload.  In this example, there is only the default content
type of ``application/octet-stream``.  We can use it to retrieve the payload:

.. code-block:: bash

    # Retrieve the payload and save it to a file
   curl -vv -H "X-Auth-Token: $TOKEN" \
   -H 'Accept: application/octet-stream' \
   -o retrieved_key \
   http://localhost:9311/v1/secrets/48d24158-b4b4-45b8-9669-d9f0ef793c23/payload

The *retrieved_key* file now contains the byte array we started with.  Note
that barbican returned the byte array in binary format, not base64.  This is
because the ``payload_content_encoding`` is only used when submitting the secret
to barbican.
