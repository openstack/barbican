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

    enable_plugin barbican https://git.openstack.org/openstack/barbican stable/liberty

For more information, see the "Externally Hosted Plugins" section of
http://docs.openstack.org/developer/devstack/plugins.html
