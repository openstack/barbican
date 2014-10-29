Plugin Developers Guide
=========================

This guide describes how to develop custom plugins for use by Barbican. While
Barbican provides useful plugin implementations, some OpenStack operators may
require customized implementations, perhaps to interact with a an existing
corporate database or service. This approach also gives flexibility to
operators of OpenStack clouds by allowing them to choose the right
implementation for their cloud.

Barbican's plugin architecture enables developers to create their own
implementations of features such as secret storage and generation, SSL
certificate generation, and event handling. The plugin pattern used defines an
abstract class, whose methods are invoked by Barbican logic (referred to as
Barbican 'core' in this guide) in a particular sequence. Typically plugins do
not interact with Barbican's data model directly, so Barbican core also handles
persisting any required information on the plugin's behalf.

In general, Barbican core will invoke a variation of the plugin's
``supports()`` method to determine if a requested action can be implemented by
the plugin. Once a supporting plugin is selected, Barbican core will invoke one
or more methods on the plugin to complete the action.

The links below provide further guidance on the various plugin types used by
Barbican, as well as configuration and deployment options.

.. toctree::
   :maxdepth: 1

   secret_store
   crypto
   certificate
