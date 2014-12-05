Running Barbican on DevStack
===================================

Currently, Barbican is not available within the default DevStack installation.
However, you can patch a DevStack installation to include Barbican in the
manual setup process below.

It is suggested that you install DevStack into an empty VM due to the number
of dependencies installed and configuration that is performed. With this in
mind, we provide an easy way of running Barbican on DevStack within a Vagrant
VM.

.. warning::

    This process takes anywhere from 10-30 minutes depending on your internet
    connection.


Easy Mode
------------

To simplify the setup process of running Barbican on DevStack, there is a
Vagrantfile that will automatically setup up a VM containing Barbican
running on Devstack.

1. Clone the Vagrantfile collection

    .. code-block:: bash

        git clone https://github.com/cloudkeep/vagrantfile-collection.git

2. Get into the ``barbican-devstack`` directory

    .. code-block:: bash

        cd vagrantfile-collection/barbican-devstack

3. Start create a new VM based on the cloned configuration

    .. code-block:: bash

        vagrant up

4. Once the VM has been successfully started and provisioned, ssh into the VM.

    .. code-block:: bash

        vagrant ssh

5. Once inside the VM, change your directory to the ``devstack`` folder.

    .. code-block:: bash

        cd /opt/stack/devstack/

6. Start DevStack

    .. code-block:: bash

        ./stack.sh


Manual Setup
---------------

These steps assume you are running within a clean Ubuntu 14.04 virtual
machine (local or cloud instance). If you are running locally, do not forget
to expose the following ports

#. Barbican - ``9311``
#. Keystone API - ``5000``
#. Keystone Admin API - ``35357``

Installation
^^^^^^^^^^^^^

.. code-block:: bash

    # Install system dependencies to start DevStack and install Barbican
    sudo apt-get update
    sudo apt-get install -y python-pip python-dev libffi-dev libssl-dev git

    # Clone DevStack and Barbican
    git clone https://git.openstack.org/cgit/openstack-dev/devstack.git
    git clone https://github.com/openstack/barbican.git

    # Patch DevStack with Barbican setup files
    cp barbican/contrib/devstack/lib/barbican devstack/lib/
    cp barbican/contrib/devstack/local.conf devstack/
    cp barbican/contrib/devstack/extras.d/70-barbican.sh devstack/extras.d/

    # Copy to setup directory
    sudo cp -R devstack/ /opt/stack/

    # Create a non-root user for DevStack
    sudo ./devstack/tools/create-stack-user.sh

    # Assign permissions to that user
    sudo chown -R stack:stack /opt/stack/

    # Set the service host to localhost (Only for Local VMs)
    sudo su - stack -c "echo \"export SERVICE_HOST=\\\"localhost\\\"\" >> .bashrc"

    # Start DevStack
    cd /opt/stack/devstack/
    ./stack.sh
