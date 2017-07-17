.. module:: barbican.plugin.interface.secret_store

===============================
Secret Store Plugin Development
===============================

This guide describes how to develop a custom secret store plugin for use by
Barbican.

Barbican supports two storage modes for secrets: a secret store mode (detailed
on this page), and a :doc:`cryptographic mode </contributor/plugin/crypto>`. The secret
store mode offloads both encryption/decryption and encrypted secret storage to
the plugin implementation. Barbican includes plugin interfaces to a Red Hat
Dogtag service and to a Key Management Interoperability Protocol (KMIP)
compliant security appliance.

Since the secret store mode defers the storage of encrypted secrets to plugins,
Barbican core does not need to store encrypted secrets into its data store,
unlike the :doc:`cryptographic mode </contributor/plugin/crypto>`. To accommodate the
discrepancy between the two secret storage modes, a secret store to
cryptographic plugin adapter has been included in Barbican core, as detailed in
:ref:`plugin-secret-store-crypto-adapter-label` section below.


``secret_store`` Module
=======================

The ``barbican.plugin.interface.secret_store`` module contains the classes
needed to implement a custom plugin.  These classes include the
``SecretStoreBase`` abstract base class which custom plugins should inherit
from, as well as several Data Transfer Object (DTO) classes used to transfer
data between Barbican and the plugin.

Data Transfer Objects
=====================

The DTO classes are used to wrap data that is passed from Barbican to the
plugin as well as data that is returned from the plugin back to Barbican.
They provide a level of isolation between the plugins and Barbican's internal
data models.

.. autoclass:: SecretDTO

.. autoclass:: AsymmetricKeyMetadataDTO

Secret Parameter Objects
========================

The secret parameter classes encapsulate information about secrets to be stored
within Barbican and/or its plugins.


.. autoclass:: SecretType

.. autoclass:: KeyAlgorithm

.. autoclass:: KeySpec


Plugin Base Class
=================

Barbican secret store plugins should implement the abstract base class
``SecretStoreBase``.  Concrete implementations of this class should be exposed
to Barbican using ``stevedore`` mechanisms explained in the configuration
portion of this guide.

.. autoclass:: SecretStoreBase
   :members:

Barbican Core Plugin Sequence
=============================

The sequence that Barbican invokes methods on ``SecretStoreBase``
depends on the requested action as detailed next. Note that these actions are
invoked via the ``barbican.plugin.resources`` module, which in turn is invoked
via Barbican's API and Worker processes.

**For secret storage actions**, Barbican core calls the following methods:

1. ``get_transport_key()`` - If a transport key is requested to upload secrets
   for storage, this method asks the plugin to provide the transport key.

2. ``store_secret_supports()`` - Asks the plugin if it can support storing a
   secret based on the ``KeySpec`` parameter information as described above.

3. ``store_secret()`` - Asks the plugin to perform encryption of an unencrypted
   secret payload as provided in the ``SecretDTO`` above, and then to store
   that secret. The plugin then returns a dictionary of information about that
   secret (typically a unique reference to that stored secret that only makes
   sense to the plugin). Barbican core will then persist this dictionary as a
   JSON attribute within its data store, and also hand it back to the plugin for
   secret retrievals later. The name of the plugin used to perform this storage
   is also persisted by Barbican core, to ensure we retrieve this secret only
   with this plugin.

**For secret retrievals**, Barbican core will select the same plugin as was
used to store the secret, and then invoke its ``get_secret()``
method to return the unencrypted secret.

**For symmetric key generation**, Barbican core calls the following methods:

1. ``generate_supports()`` -  Asks the plugin if it can support generating a
   symmetric key based on the ``KeySpec`` parameter information as described
   above.

2. ``generate_symmetric_key()`` - Asks the plugin to both generate and store a
   symmetric key based on the ``KeySpec`` parameter information. The plugin can
   then return a dictionary of information for the stored secret similar to
   the storage process above, which Barbican core will persist for later
   retrieval of this generated secret.

**For asymmetric key generation**, Barbican core calls the following methods:

1. ``generate_supports()`` - Asks the plugin if it can support generating an
   asymmetric key based on the ``KeySpec`` parameter information as described
   above.

2. ``generate_asymmetric_key()`` - Asks the plugin to both generate and store
   an asymmetric key based on the ``KeySpec`` parameter information. The plugin
   can then return an ``AsymmetricKeyMetadataDTO`` object as described above,
   which contains secret metadata for each of the three secrets generated and
   stored by this plugin: private key, public key and an optional passphrase.
   Barbican core will then persist information for these secrets, and also
   create a container to group them.

.. _plugin-secret-store-crypto-adapter-label:

The Cryptographic Plugin Adapter
================================

Barbican core includes a specialized secret store plugin used to adapt to
cryptographic plugins, called ``StoreCryptoAdapterPlugin``. This plugin
functions as a secret store plugin, but it directs secret related operations to
:doc:`cryptographic plugins </contributor/plugin/crypto>` for
encryption/decryption/generation operations. Because cryptographic plugins do
not store encrypted secrets, this adapter plugin provides this storage
capability via Barbican's data store.

This adapter plugin also uses ``stevedore`` to access and utilize cryptographic
plugins that can support secret operations.
