Running Barbican on DevStack
============================

Barbican is currently available via the plugin interface within devstack

We provide two ways of deploying a DevStack environment with a running
Barbican. The easy mode uses vagrant and automatically creates the VM
with all necessary dependencies to run DevStack. It is recommended to use
this process if it is your first time.

If you are familiar with DevStack you can use the steps in the manual
setup section to install Barbican onto your already running DevStack
installation.

.. warning::

    This process takes anywhere from 10-30 minutes depending on your internet
    connection.


Easy Mode
---------

To simplify the setup process of running Barbican on DevStack, there is a
Vagrantfile that will automatically setup up a VM containing Barbican
running on Devstack.

.. warning::

    Upon following these steps, you will not be able to use tox tools
    if you setup a shared folder. This is because making hard-links is
    required, but not permitted if the project is in a shared folder.
    If you wish to use tox, comment out the `Create Synced Folder`
    section in `barbican/devstack/barbican-vagrant/Vagrantfile`.

1. Obtain Barbican vagrant file
   If you don't already have the file then clone the repo below

    .. code-block:: bash

        git clone https://github.com/openstack/barbican.git

2. Move the ``barbican-vagrant`` directory outside of the Barbican directory
   and into your current directory for vagrant files. If you do not have one,
   then just copy it into your home directory.


    .. code-block:: bash

        cp -r barbican/devstack/barbican-vagrant <directory>

3. Get into the ``barbican-vagrant`` directory

    .. code-block:: bash

        cd barbican-vagrant

4. Start create a new VM based on the cloned configuration

    .. code-block:: bash

        vagrant up

5. Once the VM has been successfully started and provisioned, ssh into the VM.

    .. code-block:: bash

        vagrant ssh

6. Once inside the VM, change your directory to the ``devstack`` folder.

    .. code-block:: bash

        cd /opt/stack/devstack/

7. Start DevStack

    .. code-block:: bash

        ./stack.sh


Manual Setup
------------

These steps assume you are running within a clean Ubuntu 14.04 virtual
machine (local or cloud instance). If you are running locally, do not forget
to expose the following ports

#. Barbican - ``9311``
#. Keystone API - ``5000``
#. Keystone Admin API - ``35357``

Installation
^^^^^^^^^^^^

1. Make sure you are logged in as a non-root user with sudo privileges

2. Install git

    .. code-block:: bash

        sudo apt-get install git

3. Clone DevStack

    .. code-block:: bash

        git clone https://github.com/openstack-dev/devstack.git

4. Add the Barbican plugin to the local.conf file and verify the minimum
   services required are included. You can pull down a specific branch by
   appending the name to the end of the git url. If you leave the space empty
   like below, then origin/master will be pulled.

    .. code-block:: ini

        enable_plugin barbican https://git.openstack.org/openstack/barbican
        enable_service rabbit mysql key

   If this is your first time and you do not have a local.conf file, there is
   an example in the `Barbican github
   <https://github.com/openstack/barbican/tree/master/devstack>`_.
   Copy the file and place it in the devstack/ directory.

5. Start DevStack

     .. code-block:: bash

         cd devstack/
         ./stack.sh
