This directory contains the Barbican DevStack plugin.

# SoftHSM PKCS#11 backend
# -----------------------
#
# Enable dual secret stores (simple_crypto + p11_crypto) with PKCS#11 as the
# global default for functional testing:
#
#     enable_service barbican-softhsm
#
# This installs SoftHSM, initializes a token, generates MKEK/HMAC keys, and
# configures Barbican for multiple secret store support. The Zuul job
# barbican-pkcs11-tox-functional exercises this configuration.

To configure Barbican with DevStack, you will need to enable this plugin and
the Barbican service by adding one line to the [[local|localrc]] section of
your local.conf file.

To enable the plugin, add a line of the form:

    enable_plugin barbican <GITURL> [GITREF]

where

    <GITURL> is the URL of a Barbican repository
    [GITREF] is an optional git ref (branch/ref/tag).  The default is master.

For example

    enable_plugin barbican https://opendev.org/openstack/barbican stable/zed

For more information, see the "Externally Hosted Plugins" section of
https://docs.openstack.org/devstack/latest/plugins.html
