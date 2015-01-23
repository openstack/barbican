Writing and Running Barbican Tests
===================================

As a part of every code review that is submitted to the Barbican project
there are a number of gating jobs which aid in the prevention of regression
issues within Barbican. As a result, a Barbican developer should be familiar
with running Barbican tests locally.

For your convenience we provide the ability to run all tests through
the ``tox`` utility. If you are unfamiliar with tox please see
refer to the `tox documentation`_ for assistance.

.. _`tox documentation`: https://tox.readthedocs.org/en/latest/

Unit Tests
------------

Currently, we provide tox environments for Python 2.7. By default
all available test environments within the tox configuration will execute
when calling ``tox``. If you want to run them independently, you can do so
with the following commands

.. code-block:: bash

    # Executes tests on Python 2.7
    tox -e py27


.. note::

    If you do not have the appropriate Python versions available, consider
    setting up PyEnv to install multiple versions of Python. See the
    documentation regarding :doc:`/setup/dev` for more information.

Functional Tests
-----------------

Unlike running unit tests, the functional tests require Barbican and
Keystone services to be running in order to execute. For more
information on :doc:`setting up a Barbican development environment
</setup/dev>` and using :doc:`Keystone with Barbican </setup/keystone>`,
see our accompanying project documentation.

Once you have the appropriate services running and configured you can execute
the functional tests through tox.

.. code-block:: bash

    # Execute Barbican Functional Tests
    tox -e functional


By default, the functional tox job will use ``nosetests`` to execute the
functional tests. This is primarily due to nose being a very well known and
common workflow among developers. It is important to note that the gating
job will actually use ``testr`` instead of ``nosetests``. If you discover
issues while running your tests in the gate, then consider running ``testr``
or :doc:`Devstack</setup/devstack>` to more closely replicate the gating
environment.
