Using Audit Middleware with Barbican
====================================


Background
----------

`Audit middleware`_ is a python middleware logic which is added in service
request processing pipeline via paste deploy filters. Audit middleware
constructs audit event data in `CADF format`_.

Audit middleware supports delivery of CADF audit events via Oslo messaging
notifier capability. Based on `notification_driver` configuration, audit events
can be routed to messaging infrastructure (notification_driver = messagingv2)
or can be routed to a log file (notification_driver = log).

Audit middleware creates two events per REST API interaction. First event has
information extracted from request data and the second one has request outcome
(response).

.. _Audit middleware: https://docs.openstack.org/keystonemiddleware/latest/audit.html
.. _CADF format: http://www.dmtf.org/sites/default/files/standards/documents/DSP2038_1.0.0.pdf


Enabling Audit for API Requests
-------------------------------

Audit middleware is available as part of `keystonemiddleware`_ (>= 1.6) library.
Assuming a barbican deployment is already using keystone for token validation,
auditing support requires only configuration changes. It has Oslo messaging
library dependency as it uses this for audit event delivery. pyCADF library is
used for creating events in CADF format.

* Enable Middleware : `Enabling Middleware Link`_  . Change is primarily in
  service paste deploy configuration.
* Configure Middleware : `Configuring Middleware Link`_ . Can use provided
  audit mapping file. If there are no custom mapping for actions or path, then
  related mapping values are derived from taxonomy defined in pyCADF library.


.. _keystonemiddleware: https://github.com/openstack/keystonemiddleware/blob/master/keystonemiddleware/audit
.. _Enabling Middleware Link: https://docs.openstack.org/keystonemiddleware/latest/audit.html#enabling-audit-middleware
.. _Configuring Middleware Link: https://docs.openstack.org/keystonemiddleware/latest/audit.html#configure-audit-middleware


.. note::
   Audit middleware filter should be included after Keystone middleware's keystone_authtoken
   middleware in request pipeline. This is needed so that audit middleware can utilize
   environment variables set by keystone_authtoken middleware.

Steps
#####

1. Turn off any active instances of Barbican.

#. Copy *api_audit_map.conf* to ``/etc/barbican`` directory.

#. Edit ``/etc/barbican/barbican-api-paste.ini``

   Replace the /v1 app pipeline from ``barbican_api`` to
   ``barbican-api-keystone-audit`` pipeline:

   .. code-block:: text

      [pipeline:barbican-api-keystone-audit]
      pipeline = authtoken context audit apiapp

#. Edit ``barbican.conf`` to update *notification_driver* value.

#. Start Barbican ``{barbican_home}/bin/barbican.sh start``


Sample Audit Event
------------------

Following is the sample of audit event for symmetric key create request

.. code-block:: json

    {
       "priority":"INFO",
       "event_type":"audit.http.request",
       "timestamp":"2015-12-11 00:44:26.412076",
       "publisher_id":"uwsgi",
       "payload":{
          "typeURI":"http://schemas.dmtf.org/cloud/audit/1.0/event",
          "eventTime":"2015-12-11T00:44:26.410768+0000",
          "target":{
             "typeURI":"service/security/keymanager/secrets",
             "addresses":[
                {
                   "url":"http://{barbican_admin_host}:9311",
                   "name":"admin"
                },
                {
                   "url":"http://{barbican_internal_host}:9311",
                   "name":"private"
                },
                {
                   "url":"https://{barbican_public_host}:9311",
                   "name":"public"
                }
             ],
             "name":"barbican_service_user",
             "id":"barbican"
          },
          "observer":{
             "id":"target"
          },
          "tags":[
             "correlation_id?value=openstack:7e0fe4a6-e258-477e-a1c9-0fd0921a8435"
          ],
          "eventType":"activity",
          "initiator":{
             "typeURI":"service/security/account/user",
             "name":"cinder_user",
             "credential":{
                "token":"***",
                "identity_status":"Confirmed"
             },
             "host":{
                "agent":"curl/7.38.0",
                "address":"192.168.245.2"
             },
             "project_id":"8eabee0a4c4e40f882df8efbce695526",
             "id":"513e8682f23446ceb598b6b0f5c4482b"
          },
          "action":"create",
          "outcome":"pending",
          "id":"openstack:3a6a961c-9ada-4b81-9095-90968d896c41",
          "requestPath":"/v1/secrets"
       },
       "message_id":"afc3fd93-51e9-4c80-b330-983e66962265"
    }


`Ceilometer audit wiki`_ can be referred to identify meaning of different fields
in audit event to **7 "W"s of Audit and Compliance**.

.. _Ceilometer audit wiki: https://wiki.openstack.org/wiki/Ceilometer/blueprints/
    support-standard-audit-formats#CADF_Model_is_designed_to_answer_all_Audit_and_Compliance_Questions
