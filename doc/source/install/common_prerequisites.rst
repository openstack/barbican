Prerequisites
-------------

Before you install and configure the Key Manager service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        # mysql

   * Create the ``barbican`` database:

     .. code-block:: console

        CREATE DATABASE barbican;

   * Grant proper access to the ``barbican`` database:

     .. code-block:: console

        GRANT ALL PRIVILEGES ON barbican.* TO 'barbican'@'localhost' \
          IDENTIFIED BY 'BARBICAN_DBPASS';
        GRANT ALL PRIVILEGES ON barbican.* TO 'barbican'@'%' \
          IDENTIFIED BY 'BARBICAN_DBPASS';

     Replace ``BARBICAN_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: console

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ source admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``barbican`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt barbican

   * Add the ``admin`` role to the ``barbican`` user:

     .. code-block:: console

        $ openstack role add --project service --user barbican admin

   * Create the ``creator`` role:

     .. code-block:: console

        $ openstack role create creator

   * Add the ``creator`` role to the ``barbican`` user:

     .. code-block:: console

        $ openstack role add --project service --user barbican creator

   * Create the barbican service entities:

     .. code-block:: console

        $ openstack service create --name barbican --description "Key Manager" key-manager

#. Create the Key Manager service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        key-manager public http://controller:9311
      $ openstack endpoint create --region RegionOne \
        key-manager internal http://controller:9311
      $ openstack endpoint create --region RegionOne \
        key-manager admin http://controller:9311
