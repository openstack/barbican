Writing and Running Barbican Tests
==================================

As a part of every code review that is submitted to the Barbican project
there are a number of gating jobs which aid in the prevention of regression
issues within Barbican. As a result, a Barbican developer should be familiar
with running Barbican tests locally.

For your convenience we provide the ability to run all tests through
the ``tox`` utility. If you are unfamiliar with tox please see
refer to the `tox documentation`_ for assistance.

.. _`tox documentation`: https://tox.readthedocs.org/en/latest/

Unit Tests
----------

Currently, we provide tox environments for Python 2.7 and 3.5. By default
all available test environments within the tox configuration will execute
when calling ``tox``. If you want to run them independently, you can do so
with the following command:

.. code-block:: bash

    # Executes tests on Python 2.7
    tox -e py27

.. note::

    If you do not have the appropriate Python versions available, consider
    setting up PyEnv to install multiple versions of Python. See the
    documentation regarding :doc:`/contributor/dev` for more information.

.. note::

    Individual unit tests can also be run, using the following commands:

    .. code-block:: bash

        # runs a single test with the function named
        # test_can_create_new_secret_one_step
        tox -e py27 -- test_can_create_new_secret_one_step

        # runs only tests in the WhenTestingSecretsResource class and
        # the WhenTestingCAsResource class
        tox -e py27 -- '(WhenTestingSecretsResource|WhenTestingCAsResource)'

    The function name or class specified must be one located in the
    `barbican/tests` directory.

    Groups of tests can also be run with a regex match after the ``--``.
    For more information on what can be done with ``testr``, please see:
    http://testrepository.readthedocs.org/en/latest/MANUAL.html

You can also setup breakpoints in the unit tests. This can be done by
adding ``import pdb; pdb.set_trace()`` to the line of the unit test you
want to examine, then running the following command:

.. code-block:: bash

    # Executes tests on Python 2.7
    tox -e debug

.. note::

    For a list of pdb commands, please see:
    https://docs.python.org/2/library/pdb.html

**Python 3.5**

In order to run the unit tests within the Python 3.5 unit testing environment
you need to make sure you have all necessary packages installed.

- On Ubuntu/Debian::

    sudo apt-get install python3-dev

- On Fedora 21/RHEL7/CensOS7::

    sudo yum install python3-devel

- On Fedora 22 and higher::

    sudo dnf install python3-devel

You then specify to run the unit tests within the Python 3.5 environment when
invoking tox

.. code-block:: bash

    # Executes tests on Python 3.5
    tox -e py35

Functional Tests
----------------

Unlike running unit tests, the functional tests require Barbican and
Keystone services to be running in order to execute. For more
information on :doc:`setting up a Barbican development environment
</contributor/dev>` and using :doc:`Keystone with Barbican </configuration/keystone>`,
see our accompanying project documentation.

Once you have the appropriate services running and configured you can execute
the functional tests through tox.

.. code-block:: bash

    # Execute Barbican Functional Tests
    tox -e functional


By default, the functional tox job will use ``testr`` to execute the
functional tests as used in the gating job.

.. note::

    In order to run an individual functional test function, you must use the
    following command:

    .. code-block:: bash

        # runs a single test with the function named
        # test_secret_create_then_check_content_types
        tox -e functional -- test_secret_create_then_check_content_types

        # runs only tests in the SecretsTestCase class and
        # the OrdersTestCase class
        tox -e functional -- '(SecretsTestCase|OrdersTestCase)'

    The function name or class specified must be one located in the
    `functionaltests` directory.

    Groups of tests can also be run with a regex match after the ``--``.
    For more information on what can be done with ``testr``, please see:
    http://testrepository.readthedocs.org/en/latest/MANUAL.html

Remote Debugging
----------------

In order to be able to hit break-points on API calls, you must use remote
debugging. This can be done by adding ``import rpdb; rpdb.set_trace()`` to
the line of the API call you wish to test. For example, adding the
breakpoint in ``def on_post`` in ``barbican.api.controllers.secrets.py``
will allow you to hit the breakpoint when a ``POST`` is done on the
secrets URL.

.. note::

    After performing the ``POST`` the application will freeze. In order to use
    ``rpdb``, you must open up another terminal and run the following:

    .. code-block:: bash

        # enter rpdb using telnet
        telnet localhost 4444

    Once in rpdb, you can use the same commands as pdb, as seen here:
    https://docs.python.org/2/library/pdb.html

