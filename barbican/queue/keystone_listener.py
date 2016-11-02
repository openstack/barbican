# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Server-side (i.e. worker side) Keystone notification related classes and logic.
"""
import oslo_messaging
from oslo_service import service

from barbican.common import utils
from barbican import queue
from barbican.tasks import keystone_consumer


LOG = utils.getLogger(__name__)


class NotificationTask(object):
    """Task which exposes the API for consuming priority based notifications.

    The Oslo notification framework delivers notifications based on priority to
    matching callback APIs as defined in its notification listener endpoint
    list.

    Currently from Keystone perspective, `info` API is sufficient as Keystone
    send notifications at `info` priority ONLY. Other priority level APIs
    (warn, error, critical, audit, debug) are not needed here.
    """

    def __init__(self, conf):
        self.conf = conf

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        """Receives notification at info level."""
        return self.process_event(ctxt, publisher_id, event_type, payload,
                                  metadata)

    def process_event(self, ctxt, publisher_id, event_type, payload, metadata):
        """Process Keystone Event based on event_type and payload data.

        Parses notification data to identify if the event is related to delete
        project or not. In case of delete project event, it passes project_id
        to KeystoneEventConsumer logic for further processing. Barbican service
        is not interested in other events so in that case it just returns None
        as acknowledgment.

        Messaging server considers message is acknowledged when either return
        value is `oslo_messaging.NotificationResult.HANDLED` or None.

        In case of successful processing of notification, the returned value is
        `oslo_messaging.NotificationResult.HANDLED`

        In case of notification processing error, the value returned
        is oslo_messaging.NotificationResult.REQUEUE when transport
        supports this feature otherwise
        `oslo_messaging.NotificationResult.HANDLED` is returned.

        """

        LOG.debug("Input keystone event publisher_id = %s", publisher_id)
        LOG.debug("Input keystone event payload = %s", payload)
        LOG.debug("Input keystone event type = %s", event_type)
        LOG.debug("Input keystone event metadata = %s", metadata)
        project_id = self._parse_payload_for_project_id(payload)
        resource_type, operation_type = self._parse_event_type(event_type)
        LOG.debug('Keystone Event: resource type={0}, operation type={1}, '
                  'keystone id={2}'.format(resource_type, operation_type,
                                           project_id))

        if (project_id and resource_type == 'project' and
                operation_type == 'deleted'):

            task = keystone_consumer.KeystoneEventConsumer()
            try:
                task.process(project_id=project_id,
                             resource_type=resource_type,
                             operation_type=operation_type)
                return oslo_messaging.NotificationResult.HANDLED
            except Exception:
                # No need to log message here as task process method has
                # already logged it
                # TODO(john-wood-w) This really should be retried on a
                #   schedule and really only if the database is down, not
                #   for any exception otherwise tasks will be re-queued
                #   repeatedly. Revisit as part of the retry task work later.
                if self.conf.keystone_notifications.allow_requeue:
                    return oslo_messaging.NotificationResult.REQUEUE
                else:
                    return oslo_messaging.NotificationResult.HANDLED
        return None  # in case event is not project delete

    def _parse_event_type(self, event_type):
        """Parses event type provided as part of notification.

        Parses to identify what operation is performed and on which Keystone
        resource.

        A few event type sample values are provided below::
            identity.project.deleted
            identity.role.created
            identity.domain.updated
            identity.authenticate
        """
        resource_type = None
        operation_type = None
        if event_type:
            type_list = event_type.split('.')
            # 2 is min. number of dot delimiters expected in event_type value.
            if len(type_list) > 2:
                resource_type = type_list[-2].lower()
                operation_type = type_list[-1].lower()

        return resource_type, operation_type

    def _parse_payload_for_project_id(self, payload_s):
        """Gets project resource identifier from payload

        Sample payload is provided below::
            {'resource_info': u'2b99a94ad02741978e613fb52dd1f4cd'}
        """
        if payload_s:
            return payload_s.get('resource_info')


class MessageServer(NotificationTask, service.Service):
    """Server to retrieve messages from queue used by Keystone.

    This is used to send public notifications for openstack service
    consumption.

    This server is an Oslo notification server that exposes set of standard
    APIs for events consumption based on event priority.

    Some of messaging server configuration needs to match with Keystone
    deployment notification configuration e.g. exchange name, topic name
    """
    def __init__(self, conf):
        pool_size = conf.keystone_notifications.thread_pool_size
        NotificationTask.__init__(self, conf)
        service.Service.__init__(self, threads=pool_size)

        self.target = queue.get_notification_target()
        self._msg_server = queue.get_notification_server(targets=[self.target],
                                                         endpoints=[self])

    def start(self):
        self._msg_server.start()
        super(MessageServer, self).start()

    def stop(self):
        super(MessageServer, self).stop()
        self._msg_server.stop()
        queue.cleanup()
