Setting up a Barbican development environment
==============================================

These instructions are designed to help you setup a standalone version of
Barbican which uses SQLite as a database backend. This is not suitable for
production due to the lack of authentication and an interface to a secure
encryption system such as an HSM (Hardware Security Module). In addition,
the SQLite backend has known issues with thread-safety. This setup is purely
to aid in development workflows.

.. note::

    The default key store implementation in Barbican **is not secure** in
    any way. **Do not use this development standalone mode to store sensitive
    information!**


Installing system dependencies
----------------------------------------

**Ubuntu:**

.. code-block:: bash

    # Install dependencies required to build Barbican
    sudo apt-get install -y python-pip python-dev libffi-dev libssl-dev libsqlite3-dev

    # Install dependencies required for PyEnv
    sudo apt-get install -y git curl make build-essential zlib1g-dev libbz2-dev \
                            libreadline-dev

    # Install dependency for the PyEnv - virtualenvwrapper plugin
    sudo pip install virtualenvwrapper


Installing PyEnv
-----------------

PyEnv is a great utility to simplify the management of Python versions.

The official installation guide is available on the `PyEnv GitHub`_ page. However,
the following is a shortened guide based on a specific development workflow.

It's important to note that this process should be done as the user that will
be operating pyenv and not the root user.

.. _`PyEnv GitHub`: https://github.com/yyuu/pyenv#installation

**Ubuntu:**

.. code-block:: bash

    # Get PyEnv and virtualenvwrapper plugin source
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
    git clone https://github.com/yyuu/pyenv-virtualenvwrapper.git \
              ~/.pyenv/plugins/pyenv-virtualenvwrapper

    # Add PyEnv Setup to your .bashrc file
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
    echo 'pyenv virtualenvwrapper' >> ~/.bashrc

    # Activate PyEnv by reactivating your shell
    exec $SHELL


Installing clean versions of Python in PyEnv
----------------------------------------------

Installing clean versions of Python allows for us to be able to run Barbican
unit tests through tox without much difficulty. You can see the full list of
available Python versions you can install by executing: ``pyenv install -l``

For the Barbican development, we'll just be installing Python 2.6.9 and 2.7.8.

.. code-block:: bash

    # Install our Python Versions
    pyenv install 2.6.9
    pyenv install 2.7.8

    # Set PyEnv to use those versions by default
    pyenv global 2.7.8 2.6.9


Setting up a virtual environment
---------------------------------

As we installed virtualenvwrapper earlier, we'll be using it to setup our
Barbican virtual environment.

For more information regarding the usage of virtualenvwrapper, see the
`command reference`_

.. _`command reference`: http://virtualenvwrapper.readthedocs.org/en/latest/command_ref.html

.. code-block:: bash

    # Create a virtual environment
    mkvirtualenv Barbican

.. note::

    Virtualenvwrapper will attempt to reset the Python version that was active
    when you created the virtualenv. As a result, if you have the version
    2.7.8 active when you created the virtualenv, then the default Python
    version will become 2.7.8 when you reactivate the virtualenv.


Installing Barbican from source
--------------------------------

The running the ``barbican.sh install`` script available within the ``bin/``
folder will copy the appropriate configuration to the ``/etc/barbican``
directory, install all required dependencies, and start Barbican with uWSGI.

.. code-block:: bash

    # Clone Barbican
    git clone https://github.com/openstack/barbican.git
    cd barbican

    # Make sure we are in our virtual environment
    workon Barbican

    # Install Barbican
    bin/barbican.sh install

.. note::

    It's important to note that the default configuration files do not activate
    the Keystone middleware component for authentication and authorization. See
    documentation on :doc:`using keystone with Barbican <./keystone>`
