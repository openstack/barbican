Using Keystone Middleware with Barbican
========================================

Prerequisites
--------------
To enable Keystone integration with Barbican you'll need a relatively
current version of Keystone. If you don't have an instance of Keystone
available, you can use one of the following ways to setup your own.

 #. `Simple Dockerized Keystone`_
 #. `Installing Keystone`_
 #. Devstack

.. _Simple Dockerized Keystone: https://registry.hub.docker.com/u/
                                jmvrbanac/simple-keystone/
.. _Installing Keystone: http://docs.openstack.org/developer/keystone/
                         installing.html


Hooking up Barbican to Keystone
--------------------------------
Assuming that you've already setup your Keystone instance, connecting
Barbican to Keystone is quite simple. When completed, Barbican should
require a valid X-Auth-Token to be provided with all API calls except
the get version call.

1. Turn off any active instances of Barbican
2. Edit ``/etc/barbican/barbican-api-paste.ini``

   1. Replace the ``barbican_api`` pipeline with an authenticated pipeline

    .. code-block:: ini

        [pipeline:barbican_api]
        pipeline = keystone_authtoken context apiapp

   2. Replace ``keystone_authtoken`` filter values to match your Keystone
      setup

    .. code-block:: ini

       [filter:keystone_authtoken]
       paste.filter_factory = keystonemiddleware.auth_token:filter_factory
       signing_dir = /tmp/barbican/cache
       identity_uri = http://{YOUR_KEYSTONE_ENDPOINT}:35357
       admin_tenant_name = service
       admin_user = {YOUR_KEYSTONE_USERNAME}
       admin_password = {YOUR_KEYSTONE_PASSWORD}
       auth_version = v2.0

3. Start Barbican ``{barbican_home}/bin/barbican.sh start``

