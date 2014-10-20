=====================================
Troubleshooting your Barbican Setup
=====================================

If you cannot find the answers you're looking for within this document,
you can ask questions on the Freenode IRC channel ``#openstack-barbican``


Getting a Barbican HTTP 401 error after a successful authentication to Keystone
-------------------------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^^

You get a HTTP 401 Unauthorized response even with a valid token

.. code-block:: bash

    curl -X POST -H "X-Auth-Token: $TOKEN" -H "Content-type: application/json" \
    -d '{"payload": "my-secret-here", "payload_content_type": "text/plain"}' \
    http://localhost:9311/v1/secrets

Caused by
^^^^^^^^^^

Expired signing cert on the Barbican server.


How to avoid
^^^^^^^^^^^^^

Check for an expired Keystone signing certificate on your Barbican server.
Look at the expiration date in ``/tmp/barbican/cache/signing_cert.pem``. If
it is expired then follow these steps.

 #. On your Keystone server, verify that signing_cert.pem has the same
    expiration date as the one on your Barbican machine. You can normally find
    ``signing_cert.pem`` on your Keystone server in ``/etc/keystone/ssl/certs``.

 #. If the cert matches then follow these steps to create a new one

    #. Delete it from both your Barbican and Keystone servers.
    #. Edit ``/etc/keystone/ssl/certs/index.txt.attr`` and set unique_subject
       to no.
    #. Run ``keystone-manage pki_setup`` to create a new ``signing_cert.pem``
    #. The updated cert will be downloaded to your Barbican server the next
       time you hit the Barbican API.

 #. If the cert **doesn't match** then delete the ``signing_cert.pem`` from
    your Barbican server. Do not delete from Keystone. The cert from Keystone
    will be downloaded to your machine the next time you hit the Barbican API.


Returned refs use localhost instead of the correct hostname
-------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    curl -X POST \
    -H "Content-type: application/json" -H "X-Auth-Token: $TOKEN" -d \
    '{"payload": "my-secret-here", "payload_content_type": "text/plain"}' \
    http://myhostname.com/v1/secrets

    # Response:
    {
      "secret_ref": "http://localhost:9311/v1/secrets/UUID_HERE"
    }


Caused by
^^^^^^^^^^

The default configuration on the response host name is not modified to the
endpoint's host name (typically the load balancer's DNS name and port).

How to avoid
^^^^^^^^^^^^^

Change your ``barbican-api.conf`` file's ``host_href`` setting from
``localhost:9311`` to the correct host name (myhostname.com in the example
above).


Barbican's tox tests fail to run on my Mac
--------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^^

``clang: error: unknown argument: '-mno-fused-madd'``

How to avoid
^^^^^^^^^^^^^

There is a `great blog article`__ that provides more details on the error and
how to work around it. This link provides more details on the error and how
to work around it.

__ https://langui.sh/2014/03/10/wunused-command-line-argument-hard-error-in
   -future-is-a-harsh-mistress/
