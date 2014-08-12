.. module:: barbican.plugin.crypto.crypto

========================================
Cryptographic Backend Plugin Development
========================================

Barbican currently defers cryptographic operations such as encryption and
decryption to pluggable backends.  This gives flexibility to operators of
OpenStack clouds by allowing them to choose the right backend for their cloud.

While Barbican does provide a few implementations of cryptographic backend
plugins, some OpenStack operators may require a custom backend that performs
encryption, decryption and/or storage in a particular manner.

This guide describes how to develop a custom cryptographic backend plugin for
use by Barbican.

``plugin`` Module
=================

The ``barbican.crypto.plugin`` module contains the classes needed to implement
a custom plugin.  These classes include the ``CryptoPluginBase`` abstract base
class which custom plugins should inherit from, as well as several Data
Transfer Object (DTO) classes used to transfer data between Barbican and the
plugin.

Data Transfer Objects
=====================

The DTO classes are used to wrap data that is passed from Barbican to the
plugin as well as data that is returned from the plugin back to Barbican.
They provide a level of isolation between the plugins and Barbican's interal
data models.

.. autoclass:: KEKMetaDTO

.. autoclass:: EncryptDTO

.. autoclass:: DecryptDTO

.. autoclass:: GenerateDTO

Plugin Base Class
=================

Custom Barbican backends should implement the abstract base class
``CryptoPluginBase``.  Concrete implementations of this class should be exposed
to barbican using ``stevedore`` mechanisms explained later in this guide.

.. autoclass:: CryptoPluginBase
   :members:

