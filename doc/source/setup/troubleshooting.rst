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

Change your ``barbican.conf`` file's ``host_href`` setting from
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


Barbican's tox tests fail to find ffi.h on my Mac
-------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    c/_cffi_backend.c:13:10: fatal error: 'ffi.h' file not found
    ...
    ERROR: could not install deps [...]; v = InvocationError('...', 1)

How to avoid
^^^^^^^^^^^^

Be sure that xcode and cmd line tools are up to date. Easiest way is to run
``xcode-select --install`` from an OS X command line. Be sure to say yes when
asked if you want to install the command line tools. Now
``ls /usr/include/ffi/ffi.h`` should show that missing file exists, and the tox
tests should run.


Barbican's tox tests fail with "ImportError: No module named _bsddb"
-------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ImportError: No module named _bsddb

How to avoid
^^^^^^^^^^^^

Running tests via tox (which uses testr) will create a .testrepository directory containing, among other things, data files.  Those datafiles may be created with bsddb, if it is available in the environment. This can cause problems if you run in an environment that does not have bsddb.  To resolve this, delete your .testrepository directory and run tox again.


uWSGI logs 'OOPS ! failed loading app'
--------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    spawned uWSGI master process (pid: 59190)
    spawned uWSGI worker 1 (pid: 59191, cores: 1)
    spawned uWSGI worker 1 (pid: 59192, cores: 1)
    Loading paste environment: config:/etc/barbican/barbican-api-paste.ini
    WSGI app 0 (mountpoint='') ready in 0 seconds on interpreter \
        0x7fd098c08520 pid: 59191 (default app)
    OOPS ! failed loading app in worker 1 (pid 59192) :( trying again...
    Respawned uWSGI worker 1 (new pid: 59193)
    Loading paste environment: config:/etc/barbican/barbican-api-paste.ini
    OOPS ! failed loading app in worker 1 (pid 59193) :( trying again...
    worker respawning too fast !!! i have to sleep a bit (2 seconds)...
    ...

.. note:: You will not see any useful logs or stack traces with this error!


Caused by
^^^^^^^^^

The vassal (worker) processes are not able to access the datastore.


How to avoid
^^^^^^^^^^^^

Check the ``sql_connection`` in your ``barbican.conf`` file, to make sure
that it references a valid reachable database.


"Cannot register CLI option" error when importing logging
---------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    File ".../oslo_config/cfg.py", line 1275, in register_cli_opt
    raise ArgsAlreadyParsedError("cannot register CLI option")
    ArgsAlreadyParsedError: arguments already parsed: cannot register CLI option


Caused by
^^^^^^^^^

An attempt to call the olso.config's ``register_cli_opt()`` function after the
configuration arguments were 'parsed' (see the comments and method in
`the oslo.config project's cfg.py file`__ for details.

__ https://github.com/openstack/oslo.config/blob/master/oslo_config/cfg.py


How to avoid
^^^^^^^^^^^^

Instead of calling ``import barbican.openstack.common.log as logging`` to get a
logger, call ``from barbican.common import config`` with this to get a logger
to use in your source file: ``LOG = config.getLogger(__name__)``.


Responder raised TypeError: 'NoneType' object has no attribute '__getitem__'
----------------------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    2013-04-14 14:17:56 [FALCON] [ERROR] POST \
    /da71dfbc-a959-4ad3-bdab-5ee190ce7515/csrs? => Responder raised \
    TypeError: 'NoneType' object has no attribute '__getitem__'


Caused by
^^^^^^^^^

Forgetting to set your non-nullable FKs in entities you create via
``XxxxResource`` classes.


How to avoid
^^^^^^^^^^^^

Don't forget to set any FKs defined on an entity prior to using the repository
to create it.


uWSGI config issue: ``ImportError: No module named site``
---------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    uwsgi socket 0 bound to TCP address :9311 fd 3
    Python version: 2.7.3 (...)  [...]
    Set PythonHome to ./.venv
    ImportError: No module named site


Caused by
^^^^^^^^^

* Can't locate the Python virtualenv for the Barbican project.
* Either the 'broker' setting above is incorrect, or else you haven't started a
  queue process yet (such as RabbitMQ)


How to avoid
^^^^^^^^^^^^

Make sure the uWSGI config file at ``etc/barbican/barbican-api-paste.ini`` is
configured correctly (see installation steps above), esp. if the virtualenv
folder is named differently than the ``.ini`` file has.


REST Request Fails with JSON error
----------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
        title: "Malformed JSON"
    }


Caused by
^^^^^^^^^

Barbican REST server cannot parse the incoming JSON message from your REST
client.


How to avoid
^^^^^^^^^^^^

Make sure you are submitting properly formed JSON. For example, are there
commas after all but the last name/value pair in a list? Are there quotes
around all name/values that are text-based? Are the types of values matching
what is expected (i.e. integer and boolean types instead of quoted text)?

If you are using the Advanced REST Client with Chrome, and you tried to
upload a file to the secrets PUT call, not only will this fail due to the
multi-part format it uses, but it will also try to submit this file for every
REST request you make thereafter, causing this error. Close the tab/window
with the client, and restart it again.


Crypto Mime Type Not Supported when I try to run tests or hit the API
---------------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

A stack trace that has this in it (for example):

.. code-block:: text

    CryptoMimeTypeNotSupportedException: Crypto Mime Type of 'text/plain' not \
    supported


Caused by
^^^^^^^^^

The Barbican plugins are not installed into a place where the Python plugin
manager can find them.


How to avoid
^^^^^^^^^^^^

Make sure you run the ``pip install -e .``.


Python "can't find module errors" with the uWSGI scripts
--------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    *** has_emperor mode detected (fd: 6) ***
    ...
    !!! UNABLE to load uWSGI plugin: dlopen(./python_plugin.so, 10): image not \
    found !!!
    ...
    File "./site-packages/paste/deploy/loadwsgi.py", line 22, in import_string
      return pkg_resources.EntryPoint.parse("x=" + s).load(False)
    File "./site-packages/distribute-0.6.35-py2.7.egg/pkg_resources.py", line \
    2015, in load
      entry = __import__(self.module_name, globals(),globals(), ['__name__'])
    ImportError: No module named barbican.api.app
    ...
    *** Starting uWSGI 1.9.13 (64bit) on [Fri Jul  5 09:59:29 2013] ***


Caused by
^^^^^^^^^

The Barbican source modules are not found in the Python path of applications
such as uwsgi.


How to avoid
^^^^^^^^^^^^

Make sure you are running from your virtual env, and that pip was executed
**after** you activated your virtual environment. This especially includes the
``pip install -e`` command. Also, it is possible that your virtual env gets
corrupted, so you might need to rebuild it.


'unable to open database file None None' errors running scripts
---------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    File "./site-packages/sqlalchemy/engine/strategies.py", line 80, in connect
      return dialect.connect(*cargs, **cparams)
    File "./site-packages/sqlalchemy/engine/default.py", line 283, in connect
      return self.dbapi.connect(*cargs, **cparams)
    OperationalError: (OperationalError) unable to open database file None None
    [emperor] removed uwsgi instance barbican-api.ini
    ...


Caused by
^^^^^^^^^

Destination folder for the sqlite database is not found, or is not writable.


How to avoid
^^^^^^^^^^^^

Make sure the ``/var/lib/barbican/`` folder exists and is writable by the user
that is running the Barbican API process.


'ValueError: No JSON object could be decoded' with Keystoneclient middleware
----------------------------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    ...
    2013-08-15 16:55:15.759 2445 DEBUG keystoneclient.middleware.auth_token \
    [-] Token validation failure. _validate_user_token \
    ./site-packages/keystoneclient/middleware/auth_token.py:711
    ...
    2013-08-15 16:55:15.759 2445 TRACE keystoneclient.middleware.auth_token \
    raise ValueError("No JSON object could be decoded")
    2013-08-15 16:55:15.759 24458 TRACE keystoneclient.middleware.auth_token \
    ValueError: No JSON object could be decoded
    ...
    2013-08-15 16:55:15.766 2445 WARNING keystoneclient.middleware.auth_token \
    [-] Authorization failed for token ...
    2013-08-15 16:55:15.766 2445 INFO keystoneclient.middleware.auth_token \
    [-] Invalid user token - rejecting request...


Caused by
^^^^^^^^^

The ``keystoneclient`` middleware component is looking for a ``cms`` command in
``openssl`` that wasn't available before version ``1.0.1``.


How to avoid
^^^^^^^^^^^^

Update openssl.


"accept-encoding of 'gzip,deflate,sdch' not supported"
------------------------------------------------------

What you might see
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    Secret retrieval issue seen - accept-encoding of 'gzip,deflate,sdch' not \
    supported


Caused by
^^^^^^^^^

This might be an issue with the browser you are using, as performing the
request via curl doesn't seem to be affected.


How to avoid
^^^^^^^^^^^^

Other than using an command such as curl to make the REST request you may not
have many other options.
