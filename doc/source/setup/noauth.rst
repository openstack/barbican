No Auth Barbican
================

Generally barbican can be configured to use keystone like every other OpenStack
services for identity and access control. Sometimes it may be useful to run
barbican without any authentication service for development purpose.

By default, configuration in :file:`barbican-api-paste.ini` sets barbican
without any authentication (no auth mode), for example:

.. code-block:: ini

    # Use this pipeline for Barbican API - DEFAULT no authentication
    [pipeline:barbican_api]
    pipeline = unauthenticated-context apiapp


With every OpenStack service integrated with keystone, its API requires access
token to retireve certain information and validate user's information and
prviledges. If you are running barbican in no auth mode, you have to specify
project_id instead of an access token which was retrieved from the token
instead. In case of API, replace ``'X-Auth-Token: $TOKEN'`` with
``'X-Project-Id: {project_id}'`` for every API request in :doc:`../api/index`.

You can also find detailed explanation to run barbican client with an
unauthenticated context
`here <http://docs.openstack.org/developer/python-barbicanclient/authentication.html#unauthenticated-context>`_ and run barbican CLI in no auth mode
`here <http://docs.openstack.org/developer/python-barbicanclient/authentication.html#no-auth-mode>`_.
