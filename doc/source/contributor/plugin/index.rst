=========================
Plugin Developers Guide
=========================

This guide describes how to develop custom plugins for use by Barbican. While
Barbican provides useful plugin implementations, some OpenStack operators may
require customized implementations, perhaps to interact with an existing
corporate database or service. This approach also gives flexibility to
operators of OpenStack clouds by allowing them to choose the right
implementation for their cloud.

Plugin Status
=============
A Barbican plugin may be considered ``stable``, ``experimental`` or
``out-of-tree``.

* A *stable* status indicates that the plugin is fully supported by the
  OpenStack Barbican Team
* An *experimental* status indicates that we intend to support the plugin,
  but it may be missing features or may not be fully tested at the gate.
  Plugins in this status may occasionally break.
* An *out-of-tree* status indicates that no formal support will be provided,
  and the plugin may be removed in a future release.

Graduation Process
------------------
By default, new plugins proposed to be in-tree will be in the *experimental*
status.  To be considered *stable* a plugin must meet the following
requirements:

* 100% unit test coverage, including branch coverage.
* Gate job that executes the functional test suite against an instance of
  Barbican configured to use the plugin.  The gate may be a devstack gate,
  or a third-party gate.
* Implement new features within one cycle after the new blueprint feature
  is approved.

Demotion Process
----------------
Plugins should not stay in the *experimental* status for a long time.
Plugins that stay in *experimental* for more than **two** releases are
expected to move into *stable*, as described by the Graduation Process, or
move into *out-of-tree*.

Plugins in the *stable* status may be deprecated by the team, and moved to
*out-of-tree*.

Plugins that stay in the *out-of-tree* status for more than **two** releases
may be removed from the tree.

Architecture
============

Barbican's plugin architecture enables developers to create their own
implementations of features such as secret storage and generation and event handling.
The plugin pattern used defines an abstract class, whose methods are invoked by Barbican
logic (referred to as Barbican 'core' in this guide) in a particular sequence. Typically
plugins do not interact with Barbican's data model directly, so Barbican core also handles
persisting any required information on the plugin's behalf.

In general, Barbican core will invoke a variation of the plugin's
``supports()`` method to determine if a requested action can be implemented by
the plugin. Once a supporting plugin is selected, Barbican core will invoke one
or more methods on the plugin to complete the action.

The links below provide further guidance on the various plugin types used by
Barbican, as well as configuration and deployment options.

.. toctree::
   :maxdepth: 1

   secret_store.rst
   crypto.rst
