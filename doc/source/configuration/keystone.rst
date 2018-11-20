Using Keystone Middleware with Barbican
========================================

Prerequisites
--------------
To enable Keystone integration with Barbican you'll need a relatively current
version of Keystone. It is sufficient if you are installing an OpenStack cloud
where all services including Keystone and Barbican are from the same release.
If you don't have an instance of Keystone available, you can use one of the
following ways to setup your own.

#. `Simple Dockerized Keystone`_
#. `Installing Keystone`_
#. An OpenStack cloud with Keystone (Devstack in the simplest case)

.. _Simple Dockerized Keystone: https://registry.hub.docker.com/u/
                                jmvrbanac/simple-keystone/
.. _Installing Keystone: https://docs.openstack.org/keystone/latest/
                         install/index.html


Hooking up Barbican to Keystone
--------------------------------
Assuming that you've already setup your Keystone instance, connecting
Barbican to Keystone is quite simple. When completed, Barbican should
require a valid X-Auth-Token to be provided with all API calls except
the get version call.

1. Turn off any active instances of Barbican
2. Edit ``/etc/barbican/barbican-api-paste.ini``

   1. Change the pipeline ``/v1`` value from unauthenticated ``barbican_api``
      to the authenticated ``barbican-api-keystone``. This step will not be
      necessary on barbican from OpenStack Newton or higher, since barbican
      will default to using Keystone authentication as of OpenStack Newton.

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
         auth_plugin = password
         username = {YOUR_KEYSTONE_USERNAME}
         password = {YOUR_KEYSTONE_PASSWORD}
         user_domain_id = {YOUR_KEYSTONE_USER_DOMAIN}
         project_name = {YOUR_KEYSTONE_PROJECT}
         project_domain_id = {YOUR_KEYSTONE_PROJECT_DOMAIN}
         www_authenticate_uri = http://{YOUR_KEYSTONE_ENDPOINT}:5000/v3
         auth_url = http://{YOUR_KEYSTONE_ENDPOINT}:5000/v3

      Alternatively, you can shorten this to

      .. code-block:: ini

         [filter:authtoken]
         paste.filter_factory = keystonemiddleware.auth_token:filter_factory

      and store Barbican's Keystone credentials in the ``[keystone_authtoken]``
      section of ``/etc/barbican/barbican.conf``

      .. code-block:: ini

         [keystone_authtoken]
         auth_plugin = password
         username = {YOUR_KEYSTONE_USERNAME}
         password = {YOUR_KEYSTONE_PASSWORD}
         user_domain_id = {YOUR_KEYSTONE_USER_DOMAIN}
         project_name = {YOUR_KEYSTONE_PROJECT}
         project_domain_id = {YOUR_KEYSTONE_PROJECT_DOMAIN}
         www_authenticate_uri = http://{YOUR_KEYSTONE_ENDPOINT}:5000/v3
         auth_url = http://{YOUR_KEYSTONE_ENDPOINT}:5000/v3

3. Start Barbican ``{barbican_home}/bin/barbican.sh start``

