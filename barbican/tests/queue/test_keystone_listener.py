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
import uuid

import mock
import oslo_messaging
from oslo_service import service

from barbican.common import config
from barbican import queue
from barbican.queue import keystone_listener
from barbican.tasks import keystone_consumer as consumer
from barbican.tests import utils


class UtilMixin(object):

    def __init__(self, *args, **kwargs):
        super(UtilMixin, self).__init__(*args, **kwargs)
        self.conf = config.CONF
        # dict which has item as {property: (value, group_name)}
        self.overrides = {}

    def revert_overrides(self):
        '''Reverts configuration override values after test end.'''
        for k, v in self.overrides.items():
            value, group = v
            self.conf.set_override(k, value, group)

    def setUp(self):
        super(UtilMixin, self).setUp()
        self.addCleanup(self.revert_overrides)

    def opt_in_group(self, group, **kw):
        for k, v in kw.items():
            # add to local overrides if its not already set
            # we want to keep the original value from first override
            dict_value = self.overrides.get(k)
            if not dict_value:
                if group:
                    orig_value = getattr(getattr(self.conf, group), k)
                else:
                    orig_value = getattr(self.conf, k)
                self.overrides[k] = orig_value, group
            self.conf.set_override(k, v, group)


class WhenUsingNotificationTask(UtilMixin, utils.BaseTestCase):
    """Test for 'Notification' task functionality."""

    def setUp(self):
        super(WhenUsingNotificationTask, self).setUp()

        self.task = keystone_listener.NotificationTask(self.conf)
        self.payload = {'resource_info': uuid.uuid4().hex}

        self.type_index = 2
        self.payload_index = 3
        self.task_args = ['my_context', 'publisher_id', 'event_type',
                          self.payload, {'metadata': 'value'}]

    @mock.patch.object(keystone_listener.NotificationTask, 'process_event')
    def test_info_level_notification(self, mock_process):
        self.task.info(*self.task_args)
        mock_process.assert_called_once_with(*self.task_args)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_create_project_event_notification(self, mock_process):

        self.task_args[self.type_index] = 'identity.project.created'
        result = self.task.info(*self.task_args)
        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project create event')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_update_project_event_notification(self, mock_process):

        self.task_args[self.type_index] = 'identity.project.updated'
        result = self.task.info(*self.task_args)
        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project update event')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_notification_with_required_data(
            self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)
        mock_process.assert_called_once_with(project_id=project_id,
                                             operation_type='deleted',
                                             resource_type='project')
        self.assertEqual(oslo_messaging.NotificationResult.HANDLED, result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_with_different_service_name_in_event_type(
            self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'aaa.project.deleted'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)

        mock_process.assert_called_once_with(project_id=project_id,
                                             operation_type='deleted',
                                             resource_type='project')
        self.assertEqual(oslo_messaging.NotificationResult.HANDLED, result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_with_event_type_in_different_case(
            self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'Identity.PROJECT.DeleteD'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)

        mock_process.assert_called_once_with(project_id=project_id,
                                             operation_type='deleted',
                                             resource_type='project')
        self.assertEqual(oslo_messaging.NotificationResult.HANDLED, result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_with_incomplete_event_type_format(
            self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'project.deleted'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project delete event as service name is missing '
                         'in event_type data. Expected format is '
                         ' <service_name>.<resource_name>.<operation_type>')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_notification_with_missing_resource_info(
            self, mock_process):

        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = {'resource_info': None}
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project delete event when project_id is missing '
                         'in payload')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_notification_with_missing_payload(
            self, mock_process):

        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = None
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project delete event when payload is missing')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_delete_project_event_notification_with_blank_payload(
            self, mock_process):

        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = ''
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for project delete event when payload is missing')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_event_notification_with_missing_event_type(self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = None
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'for keystone event when event_type is missing in '
                         'notification')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process',
                       return_value=None)
    def test_event_notification_with_blank_event_type(self, mock_process):

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = ''
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = self.task.info(*self.task_args)

        self.assertFalse(mock_process.called, 'Should not call event consumer '
                         'keystone event when event_type is blank in '
                         'notification')
        self.assertIsNone(result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process')
    def test_event_notification_with_processing_error_requeue_disabled(
            self, mock_process):

        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME, allow_requeue=False)
        local_task = keystone_listener.NotificationTask(self.conf)
        mock_process.side_effect = Exception('Dummy Error')

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = local_task.info(*self.task_args)

        self.assertTrue(mock_process.called, 'Should call event consumer for'
                        ' project delete event')
        self.assertEqual(oslo_messaging.NotificationResult.HANDLED, result)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'process')
    def test_event_notification_with_processing_error_requeue_enabled(
            self, mock_process):

        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME, allow_requeue=True)
        local_task = keystone_listener.NotificationTask(self.conf)
        mock_process.side_effect = Exception('Dummy Error')

        project_id = uuid.uuid4().hex
        self.task_args[self.type_index] = 'identity.project.deleted'
        self.task_args[self.payload_index] = {'resource_info': project_id}
        result = local_task.info(*self.task_args)

        self.assertTrue(mock_process.called, 'Should call event consumer for'
                        ' project delete event')
        self.assertEqual(oslo_messaging.NotificationResult.REQUEUE, result)


class WhenUsingMessageServer(UtilMixin, utils.BaseTestCase):
    """Test using the asynchronous task client."""

    def setUp(self):
        super(WhenUsingMessageServer, self).setUp()
        queue.init(self.conf)

        patcher = mock.patch('oslo_messaging.server.MessageHandlingServer')
        mock_server_class = patcher.start()
        self.addCleanup(patcher.stop)

        self.msg_server_mock = mock_server_class()
        self.msg_server_mock.start.return_value = None
        self.msg_server_mock.stop.return_value = None
        self.msg_server_mock.wait.return_value = None

    @mock.patch.object(queue, 'get_notification_server')
    @mock.patch.object(queue, 'get_notification_target')
    def test_target_and_notification_server_invocations(self, mock_target,
                                                        mock_server):
        target = 'a target value here'
        mock_target.return_value = target
        msg_server = keystone_listener.MessageServer(self.conf)

        mock_target.assert_called_once_with()
        mock_server.assert_called_once_with(
            targets=[target], endpoints=[msg_server])

    def test_keystone_notification_config_used(self):
        topic = 'my test topic'
        exchange = 'my test exchange'
        version = ' my test version'
        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME, topic=topic)
        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME,
                          control_exchange=exchange)
        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME, version=version)
        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME, version=version)
        target = queue.get_notification_target()
        self.assertEqual(topic, target.topic)
        self.assertEqual(exchange, target.exchange)
        self.assertEqual(version, target.version)

    @mock.patch.object(service.Service, '__init__')
    def test_keystone_notification_pool_size_used(self, mock_service_init):
        thread_pool_size = 5
        self.opt_in_group(queue.KS_NOTIFICATIONS_GRP_NAME,
                          thread_pool_size=thread_pool_size)
        msg_server = keystone_listener.MessageServer(self.conf)
        mock_service_init.assert_called_once_with(msg_server,
                                                  threads=thread_pool_size)

    @mock.patch.object(service.Service, 'start')
    def test_should_start(self, mock_service):
        msg_server = keystone_listener.MessageServer(self.conf)
        msg_server.start()
        self.msg_server_mock.start.assert_called_with()

    @mock.patch.object(service.Service, 'stop')
    def test_should_stop(self, mock_service_stop):
        msg_server = keystone_listener.MessageServer(self.conf)
        msg_server.stop()
        self.msg_server_mock.stop.assert_called_with()

    @mock.patch.object(service.Service, 'wait')
    def test_should_wait(self, mock_service_wait):
        msg_server = keystone_listener.MessageServer(self.conf)
        msg_server.wait()
        self.assertFalse(self.msg_server_mock.stop.called, 'No need to call'
                         'message server wait() as Service itself creates the '
                         ' wait event')
        self.assertTrue(mock_service_wait.called, 'Expected to only call '
                        'service.Service.wait() method')
