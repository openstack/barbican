.. module:: barbican.plugin.crypto.crypto

================================
Cryptographic Plugin Development
================================

This guide describes how to develop a custom cryptographic plugin for use by
Barbican.

Barbican supports two storage modes for secrets: a cryptographic mode (detailed
on this page), and a :doc:`secret store mode </plugin/secret_store>`. The
cryptograpic mode stores encrypted secrets in Barbican's data store, utilizing
a cryptographic process or appliance (such as a hardware security module (HSM))
to perform the encryption/decryption. Barbican includes a PKCS11-based
interface to SafeNet HSMs.

Note that cryptographic plugins are not invoked directly from Barbican core,
but rather via a :doc:`secret store mode </plugin/secret_store>` plugin adapter
class, further described in :ref:`plugin-secret-store-crypto-adapter-label`.

``crypto`` Module
=================

The ``barbican.plugin.crypto`` module contains the classes needed to implement
a custom plugin.  These classes include the ``CryptoPluginBase``
abstract base class which custom plugins should inherit from, as well as
several Data Transfer Object (DTO) classes used to transfer data between
Barbican and the plugin.

Data Transfer Objects
=====================

The DTO classes are used to wrap data that is passed from Barbican to the
plugin as well as data that is returned from the plugin back to Barbican.
They provide a level of isolation between the plugins and Barbican's internal
data models.

.. autoclass:: KEKMetaDTO

.. autoclass:: EncryptDTO

.. autoclass:: DecryptDTO

.. autoclass:: GenerateDTO

.. autoclass:: GenerateDTO

Plugin Base Class
=================

Barbican cryptographic plugins should implement the abstract base class
``CryptoPluginBase``.  Concrete implementations of this class should be exposed
to barbican using ``stevedore`` mechanisms explained in the configuration
portion of this guide.

.. autoclass:: CryptoPluginBase
   :members:

Barbican Core Plugin Sequence
=============================

Barbican invokes a different sequence of methods on the ``CryptoPluginBase``
plugin depending on the requested action. Note that these actions are invoked
via the secret store adapter class ``StoreCryptoAdapterPlugin`` which is further
described in :ref:`plugin-secret-store-crypto-adapter-label`.

**For secret storage actions**, Barbican core calls the following methods:

1. ``supports()`` - Asks the plugin if it can support the
   ``barbican.plugin.crypto.crypto.PluginSupportTypes.ENCRYPT_DECRYPT``
   operation type.

2. ``bind_kek_metadata()`` - Allows a plugin to bind an internal key encryption
   key (KEK) to a project-ID, typically as a 'label' or reference to the actual
   KEK stored within the cryptographic appliance. This KEK information is stored
   into Barbican's data store on behalf of the plugin, and then provided back to
   the plugin for subsequent calls.

3. ``encrypt()`` - Asks the plugin to perform encryption of an unencrypted secret
   payload, utilizing the KEK bound to the project-ID above. Barbican core will
   then persist the encrypted data returned from this method for later
   retrieval. The name of the plugin used to perform this encryption is also
   persisted into Barbican core, to ensure we decrypt this secret only with
   this plugin.

**For secret decryptions and retrievals**, Barbican core will select the same
plugin as was used to store the secret, and then invoke its ``decrypt()``
method, providing it both the previously-persisted encrypted secret data as well
as the project-ID KEK used to encrypt the secret.

**For symmetric key generation**, Barbican core calls the following methods:

1. ``supports()`` - Asks the plugin if it can support the
   ``barbican.plugin.crypto.crypto.PluginSupportTypes.SYMMETRIC_KEY_GENERATION``
   operation type.

2. ``bind_kek_metadata()`` - Same comments as for secret storage above.

3. ``generate_symmetric()`` - Asks the plugin to both generate a symmetric key, and
   then encrypted it with the project-ID KEK. Barbican core persists this
   newly generated and encrypted secret similar to secret storage above.

**For asymmetric key generation**, Barbican core calls the following methods:

1. ``supports()`` - Asks the plugin if it can support the
   ``barbican.plugin.crypto.crypto.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION``
   operation type.

2. ``bind_kek_metadata()`` - Same comments as for secret storage above.

3. ``generate_asymmetric()`` - Asks the plugin to generate and encrypt asymmetric
   public and private key (and optional passphrase) information, which Barbican
   core will persist as a container of separate encrypted secrets.
