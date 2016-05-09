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

   1. Change the pipeline ``/v1`` value from unauthenticated ``barbican-api``
      to the authenticated ``barbican-api-keystone``

    .. code-block:: ini

        [composite:main]
        use = egg:Paste#urlmap
        /: barbican_version
        /v1: barbican-api-keystone

   2. Replace ``authtoken`` filter values to match your Keystone
      setup

    .. code-block:: ini

       [filter:authtoken]
       paste.filter_factory = keystonemiddleware.auth_token:filter_factory
       signing_dir = /tmp/barbican/cache
       auth_uri = http://{YOUR_KEYSTONE_ENDPOINT}:5000/v3
       auth_url = http://{YOUR_KEYSTONE_ENDPOINT}:35357/v3
       auth_plugin = password
       username = {YOUR_KEYSTONE_USERNAME}
       password = {YOUR_KEYSTONE_PASSWORD}
       user_domain_id = {YOUR_KEYSTONE_USER_DOMAIN}
       project_name = {YOUR_KEYSTONE_PROJECT}
       project_domain_id = {YOUR_KEYSTONE_PROJECT_DOMAIN}

3. Start Barbican ``{barbican_home}/bin/barbican.sh start``

