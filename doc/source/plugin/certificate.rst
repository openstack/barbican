.. module:: barbican.plugin.interface.certificate_manager

==============================
Certificate Plugin Development
==============================

This guide describes how to develop a custom certificate plugin for use by
Barbican.

Barbican core orchestrates generating SSL certificates, delegating to
certificate plugins any required actions. Certificate actions include
initiating a certificate order, checking for order updates, and retrieving
generated certificates. Barbican plans to include the following certificate
plugins:

1. A Red Hat Dogtag certificate authority (CA) plugin capable of generating
   certificates once the order is initiated.

2. A Symantec plugin able to interact with the Symantec CA service, requiring
   periodic status updates to see if certificates are ready.

3. A DigiCert plugin able to interact with the DigiCert CA service, with a
   similar interactions as with Symantec.




``certificate_manager`` Module
==============================

The ``barbican.plugin.interface.certificate_manager`` module contains the
classes needed to implement a custom plugin.  These classes include the
``CertificatePluginBase`` abstract base class which custom plugins should
inherit from, as well as any Data Transfer Object (DTO) classes used to pass
information into and from plugin methods.


Data Transfer Objects
=====================

The DTO classes are used to wrap data that is passed from Barbican to the
plugin as well as data that is returned from the plugin back to Barbican.
They provide a level of isolation between the plugins and Barbican's internal
data models.

.. autoclass:: ResultDTO


.. _plugin-certificate-status-label:

Certificate Status Class
========================

When certificate plugin methods are invoked, they return a ``ResultDTO`` that
includes one of the status response constants defined by the
``CertificateStatus`` class. As detailed in the
:ref:`plugin-certificate-sequence-label` section below Barbican core directs
follow on processing for a certificate order based on these returned status
constants.

.. autoclass:: CertificateStatus
   :members:


Certificate Parameter Objects
=============================

Two dictionaries are available to most certificate plugin methods:

1. ``order_meta`` - A dictionary of values provided by the client when they
   initiated the Barbican certificate order, including information needed to
   create a certificate, such as CSR.

2. ``plugin_meta`` - A dictionary of values determined by the plugin itself
   on behalf of a specific certificate order. Barbican core persists this
   dictionary into the Barbican data store for a given order, and then provides
   this data back plugin method invocations thereafter.

   Plugins are free to update this data as required, or else ignore to it if not
   required. For example, plugins that interact with remote CAs could store the
   CA's unique order ID, for use with future interactions with that CA.


Plugin Base Class
=================

Barbican secret store plugins should implement the abstract base class
``CertificatePluginBase``. Concrete plugin implementations of
``CertificatePluginBase`` should be exposed to Barbican using ``stevedore``
mechanisms explained in the configuration portion of this guide.

.. autoclass:: CertificatePluginBase
   :members:


Barbican Order's Status Versus ResultDTO's Status
=================================================

When Barbican starts processing orders, it sets the order's ``status``
attribute to ``PENDING``. Barbican will invoke methods on the certificate
plugin to process the order, and most of those methods return a ``ResultDTO``
result object, which also has a ``status`` field. Barbican core uses the
result's ``status`` to determine follow on processing for the order as
detailed in :ref:`plugin-certificate-sequence-label` below.

The result's ``status`` field should be set to one of the constants defined
in ``CertificateStatus``, per :ref:`plugin-certificate-status-label` above. If
the result's ``status`` calls for terminating the order, Barbican core will set
the order's status to either ``ACTIVE`` or ``ERROR``. Otherwise the order's
``status`` will stay ``PENDING``, and the order's ``sub_status`` and
``sub_status_message`` will be updated with the result's ``status`` and
``status_message`` respectively.

Clients that wish to track the progress of potentially long running certificate
orders can poll the order, using the ``sub_status`` and ``sub_status_message``
to track the results. Hence plugins should provide a meaningful
message for ``sub_status_message``, especially on error conditions.


.. _plugin-certificate-sequence-label:

Barbican Core Plugin Sequence
=============================

The sequence that Barbican invokes methods on ``CertificatePluginBase`` is
detailed next. Note that these methods are invoked via the
``barbican.tasks.certificate_resources`` module, which in turn is invoked via
Barbican's Worker processes.

Barbican core calls the following methods:

1. ``supports()`` -  Asks the plugin if it can support generating a certificate
   based on the Barbican order's ``order_meta``.

2. ``issue_certificate_request()`` - Asks the plugin to initiate a certificate
   order from the provided ``order_meta`` parameter information. An empty
   dictionary is passed in for the ``plugin_meta`` parameter, which the plugin
   can update as it sees fit. Barbican core will persist and then provide the
   ``plugin_meta`` for subsequent method calls for this order.

   The plugin method returns a ``ResultDTO`` instance which Barbican core uses
   to determine subsequent order processing based on its ``status`` field. This
   ``status`` field should be set to one of the constants defined in
   ``CertificateStatus`` per :ref:`plugin-certificate-status-label` above.

   If ``status`` is ``CertificateStatus.WAITING_FOR_CA`` then Barbican core
   will invoke the ``check_certificate_status`` method after the delay
   specified in the result's ``retry_msec`` field.

   If ``status`` is ``CertificateStatus.CERTIFICATE_GENERATED`` then Barbican
   core expects that this order is completed and sets its ``status`` to
   ``ACTIVE``. Barbican also expects that the result's ``certificate`` and
   (optionally) ``intermediates`` fields are filled out with PEM-formatted SSL
   certificate data. Barbican will then create a
   ``barbican.model.models.Container`` record with
   ``barbican.model.models.Secret`` records to hold the certificate data.

   If ``status`` is ``CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST`` then
   Barbican core will invoke the same method after the delay specified in the
   result's ``retry_msec`` field. This condition typically means that a remote
   CA was not available, so should be retried in the future.

   If ``status`` is set to ``CertificateStatus.CLIENT_DATA_ISSUE_SEEN`` then
   Barbican considers the order to have problems with the client-provided data,
   but otherwise the order is viable. Barbican will keep the order in the
   ``PENDING`` state, and update the order's ``sub_status`` to
   ``CertificateStatus.CLIENT_DATA_ISSUE_SEEN`` and ``sub_status_message`` to
   the result's ``status_message``.

   Note that client data issues can include missing or incorrect information
   that the CA reports on. The CA still considers the order open, but clients
   must provide updates to correct the data. Since the client could either
   update this order via Barbican, or else work directly with a remote CA,
   Barbican will invoke the ``check_certificate_status`` method after the delay
   specified in the result's ``retry_msec`` field.

   If ``status`` is set to ``CertificateStatus.REQUEST_CANCELED`` then Barbican
   core expects that this order is completed and sets its ``status`` to
   ``ACTIVE``. It also updates the order's ``sub_status`` and
   ``sub_status_message`` to the result's status information. This condition
   could arise (for example) if a remote CA indicated that the certificate
   order is cancelled.

   If ``status`` is set to ``CertificateStatus.INVALID_OPERATION`` (or else
   the plugin raises an exception) then Barbican core considers this a failed
   order and sets the order's ``status`` to ``ERROR``. It also updates the
   order's ``sub_status`` and ``sub_status_message`` to the result's status
   information.

3. ``check_certificate_status()`` - This method is called as needed after the
   ``issue_certificate_request()`` method and is intended to allow plugins to
   check to see if a certificate has been issued yet.

   The result's ``status`` is processed similarly to the
   ``issue_certificate_request()`` method.

4. ``modify_certificate_request`` - This method is invoked if clients provide
   updates to the order metadata after the certificate order has been
   initiated.

   The result's ``status`` is processed similarly to the
   ``issue_certificate_request()`` method.

5. ``cancel_certificate_request`` - This method is invoked if clients delete
   or cancel a certificate order.

   Note that if a remote CA is involved the cancellation may not be processed
   immediately, in which case Barbican core will invoke the
   ``check_certificate_status`` method after the delay specified in the
   result's ``retry_msec`` field. Otherwise the result's ``status`` is
   processed similarly to the ``issue_certificate_request()`` method.
