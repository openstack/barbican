Setting up Certificate Plugins
==============================

Using the SnakeOil CA plugin
----------------------------

To evaluate Barbican certificate management, you can enable the snakeoil_ca
certificate plugin. This is not suitable for production environment, but it can
be useful as a development tool.

To do so, you simply need to set ``enabled_certificate_plugins`` in
``barbican.conf``.

.. code-block:: text

    enabled_certificate_plugins = snakeoil_ca

And then restart your Barbican server. It will automatically generate an
in-memory CA to create certificates.
