No Auth barbican
================

As of OpenStack Newton, barbican will default to using Keystone like every
other OpenStack service for identity and access control. Nonetheless, sometimes
it may be useful to run barbican without any authentication service for
development purposes.

To this end, ``barbican-api-paste.ini`` contains a filter pipeline
without any authentication (no auth mode):

.. code-block:: ini

   # Use this pipeline for barbican API - DEFAULT no authentication
   [pipeline:barbican_api]
   pipeline = unauthenticated-context apiapp

To enable this pipeline proceed as follows:

1. Turn off any active instances of barbican

2. Edit ``/etc/barbican/barbican-api-paste.ini``

   Change the pipeline ``/v1`` value from authenticated ``barbican-api-keystone``
   to the unauthenticated ``barbican_api``

   .. code-block:: ini

      [composite:main]
      use = egg:Paste#urlmap
      /: barbican_version
      /v1: barbican_api

With every OpenStack service integrated with keystone, its API requires access
token to retireve certain information and validate user's information and
privileges. If you are running barbican in no auth mode, you have to specify
project_id instead of an access token which was retrieved from the token
instead. In case of API, replace ``'X-Auth-Token: $TOKEN'`` with
``'X-Project-Id: {project_id}'`` for every API request in :doc:`../api/index`.

You can also find detailed explanation to run barbican client with an
unauthenticated context
`here <https://docs.openstack.org/python-barbicanclient/latest/cli/authentication.html#unauthenticated-context>`__ and run barbican CLI in no auth mode
`here <https://docs.openstack.org/python-barbicanclient/latest/cli/authentication.html#no-auth-mode>`__.
