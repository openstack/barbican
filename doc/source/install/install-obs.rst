.. _install-obs:


Install and configure for openSUSE and SUSE Linux Enterprise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the Key Manager service
for openSUSE Leap 42.2 and SUSE Linux Enterprise Server 12 SP2.

.. include:: common_prerequisites.rst

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # zypper install openstack-barbican-api openstack-barbican-keystone-listener openstack-barbican-worker

.. include:: common_configure.rst


Finalize installation
---------------------

#. Copy the sample Apache vhost file into place:

.. code-block:: console

   # cp /etc/apache2/conf.d/barbican-api.conf.sample /etc/apache2/vhosts.d/barbican-api.conf

#.  Start the Apache HTTP service and configure it to start when the system boots:

    .. code-block:: console

        # systemctl enable apache2.service
        # systemctl start apache2.service
