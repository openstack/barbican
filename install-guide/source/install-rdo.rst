.. _install-rdo:

Install and configure for Red Hat Enterprise Linux and CentOS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


This section describes how to install and configure the Key Manager service
for Red Hat Enterprise Linux 7 and CentOS 7.

.. include:: common_prerequisites.rst

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # yum install openstack-barbican-api

.. include:: common_configure.rst

Finalize installation
---------------------

#. Create the ``/etc/httpd/conf.d/wsgi-barbican.conf`` file with the following content:

   .. code-block:: apache

      <VirtualHost [::1]:9311>
          ServerName controller

          ## Logging
          ErrorLog "/var/log/httpd/barbican_wsgi_main_error_ssl.log"
          LogLevel debug
          ServerSignature Off
          CustomLog "/var/log/httpd/barbican_wsgi_main_access_ssl.log" combined

          WSGIApplicationGroup %{GLOBAL}
          WSGIDaemonProcess barbican-api display-name=barbican-api group=barbican processes=2 threads=8 user=barbican
          WSGIProcessGroup barbican-api
          WSGIScriptAlias / "/usr/lib/python2.7/site-packages/barbican/api/app.wsgi"
          WSGIPassAuthorization On
      </VirtualHost>

#.  Start the Apache HTTP service and configure it to start when the system boots:

    .. code-block:: console

        # systemctl enable httpd.service
        # systemctl start httpd.service
