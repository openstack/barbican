.. _install-ubuntu:

Install and configure for Ubuntu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the Key Manager
service for Ubuntu 14.04 (LTS).

.. include:: common_prerequisites.rst

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # apt-get update

      # apt-get install barbican-api barbican-keystone-listener barbican-worker

.. include:: common_configure.rst

Finalize installation
---------------------

Restart the Key Manager services:

.. code-block:: console

   # service barbican-keystone-listener restart
   # service barbican-worker restart
   # service apache2 restart
