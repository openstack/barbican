Setting up a Barbican Development Environment
==============================================

These instructions are designed to help you setup a standalone version of
Barbican which uses SQLite as a database backend. This is not suitable for
production due to the lack of authentication and an interface to a secure
encryption system such as an HSM (Hardware Security Module). In addition,
the SQLite backend has known issues with thread-safety. This setup is purely
to aid in development workflows.

Installing system dependencies
------------------------------

**Ubuntu 15.10:**

.. code-block:: bash

    # Install development tools
    sudo apt-get install git python-tox

    # Install dependency build requirements
    sudo apt-get install libffi-dev libssl-dev python-dev gcc

**Fedora 30:**

.. code-block:: bash

    # Install development tools
    sudo dnf install git python3-tox

    # Install dependency build requirements
    sudo dnf install gcc libffi-devel openssl-devel redhat-rpm-config

Setting up a virtual environment
--------------------------------

We highly recommend using virtual environments for development.  You can learn
more about `Virtual Environments`_ in The Python Tutorial.

If you installed tox in the previous step you should already have virtualenv
installed as well.

.. _Virtual Environments: https://docs.python.org/3/tutorial/venv.html

.. code-block:: bash

    # Clone barbican source
    git clone https://opendev.org/openstack/barbican
    cd barbican

    # Create and activate a virtual environment
    virtualenv .barbicanenv
    . .barbicanenv/bin/activate

    # Install barbican in development mode
    pip install -e $PWD

Configuring Barbican
--------------------

Barbican uses oslo.config for configuration.  By default the api process will
look for the configuration file in ``$HOME/barbican.conf`` or
``/etc/barbican/barbican.conf``.  The sample configuration files included in the
source code assume that you'll be using ``/etc/barbican/`` for configuration and
``/var/lib/barbican`` for the database file location.

.. code-block:: bash

   # Create the directories and copy the config files
   sudo mkdir /etc/barbican
   sudo mkdir /var/lib/barbican
   sudo chown $(whoami) /etc/barbican
   sudo chown $(whoami) /var/lib/barbican
   cp -r etc/barbican /etc
   tox -e genconfig
   cp etc/oslo-config-generator/barbican.conf /etc/barbican/barbican.conf
   sed -i 's/\/v1: barbican-api-keystone/\/v1: barbican_api/' /etc/barbican/barbican-api-paste.ini

All the locations are configurable, so you don't have to use ``/etc`` and
``/var/lib`` in your development machine if you don't want to.

Running Barbican
----------------

If you made it this far you should be able to run the barbican development
server using this command:

.. code-block:: bash

   bin/barbican-api

An instance of barbican will be listening on ``http://localhost:9311``.  Note
that the default configuration uses the unauthenticated context.  This means
that requests should include the ``X-Project-Id`` header instead of including
a keystone token in the ``X-Auth-Token`` header.  For example:

.. code-block:: bash

   curl -v -H 'X-Project-Id: 12345' \
           -H 'Accept: application/json' \
           http://localhost:9311/v1/secrets

For more information on configuring Barbican with Keystone auth see the
:doc:`Keystone Configuration </configuration/keystone>` page.

Building the Documentation
--------------------------

You can build the html documentation using tox:

.. code-block:: bash

   tox -e docs


Running the Unit Tests
----------------------

You can run the unit test suite using tox:

.. code-block:: bash

   tox -e py36
