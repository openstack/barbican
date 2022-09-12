Running Barbican on DevStack
============================

Barbican is currently available via the plugin interface within DevStack.

This installation guide assumes you are running devstack within a clean virtual
machine (local or cloud instance) using one of the `supported Linux
distributions`_ with all available system package updates.

.. _`supported Linux distributions`: https://governance.openstack.org/tc/reference/project-testing-interface.html#linux-distributions

#. Make sure you are logged in as the "stack" user with sudo privileges

#. Install git

   .. code-block:: bash

       # Debian/Ubuntu
       sudo apt-get install git

       # CentOS
       sudo dnf install git

3. Clone DevStack

   .. code-block:: bash

       git clone https://opendev.org/openstack/devstack.git
       cd devstack/

4. Add the Barbican plugin to the ``local.conf`` file and verify the
   minimum services required are included. You can pull down a specific branch
   by appending the name to the end of the git URL. If you leave the space
   empty like below, then origin/master will be pulled.

   .. code-block:: ini

       enable_plugin barbican https://opendev.org/openstack/barbican
       enable_service rabbit mysql key

   If this is your first time and you do not have a ``local.conf`` file, there
   is a working sample file in the `Barbican repository`_.
   Copy the file and place it in the ``devstack/`` directory.

   .. _`Barbican repository`: https://opendev.org/openstack/barbican/src/branch/master/devstack/local.conf.example

5. Start DevStack

   .. code-block:: bash

       ./stack.sh
