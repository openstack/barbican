This directory contains the Barbican DevStack plugin.

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
