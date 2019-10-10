2. Edit the ``/etc/barbican/barbican.conf`` file and complete the following
   actions:

   * In the ``[DEFAULT]`` section, configure database access:

     .. code-block:: ini

        [DEFAULT]
        ...
        sql_connection = mysql+pymysql://barbican:BARBICAN_DBPASS@controller/barbican

     Replace ``BARBICAN_DBPASS`` with the password you chose for the
     Key Manager service database.

   * In the ``[DEFAULT]`` section,
     configure ``RabbitMQ`` message queue access:

     .. code-block:: ini

        [DEFAULT]
        ...
        transport_url = rabbit://openstack:RABBIT_PASS@controller

     Replace ``RABBIT_PASS`` with the password you chose for the
     ``openstack`` account in ``RabbitMQ``.

   * In the ``[keystone_authtoken]`` section, configure Identity
     service access:

     .. code-block:: ini

        [keystone_authtoken]
        ...
        www_authenticate_uri = http://controller:5000
        auth_url = http://controller:5000
        memcached_servers = controller:11211
        auth_type = password
        project_domain_name = default
        user_domain_name = default
        project_name = service
        username = barbican
        password = BARBICAN_PASS

     Replace ``BARBICAN_PASS`` with the password you chose for the
     ``barbican`` user in the Identity service.

     .. note::

        Comment out or remove any other options in the
        ``[keystone_authtoken]`` section.

#. Populate the Key Manager service database:

   If you wish the Key Manager service to automatically populate the
   database when the service is first started, set db_auto_create to
   True in the ``[DEFAULT]`` section. By default this will not be active
   and you can populate the database manually as below:

   .. code-block:: console

      $ su -s /bin/sh -c "barbican-manage db upgrade" barbican

   .. note::

      Ignore any deprecation messages in this output.

#.  Barbican has a plugin architecture which allows the deployer to store secrets in
    a number of different back-end secret stores.  By default, Barbican is configured to
    store secrets in a basic file-based keystore.  This key store is NOT safe for
    production use.

    For a list of supported plugins and detailed instructions on how to configure them,
    see :ref:`barbican_backend`
