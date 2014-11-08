# Copyright (c) 2013-2014 Rackspace, Inc.
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
Queue objects for Cloudkeep's Barbican
"""
from oslo.config import cfg
from oslo import messaging
from oslo.messaging.notify import dispatcher as notfiy_dispatcher
from oslo.messaging import server as msg_server

from barbican.common import exception
from barbican.common import utils
from barbican.openstack.common import gettextutils as u


LOG = utils.getLogger(__name__)

queue_opt_group = cfg.OptGroup(name='queue',
                               title='Queue Application Options')

queue_opts = [
    cfg.BoolOpt('enable', default=False,
                help=u._('True enables queuing, False invokes '
                         'workers synchronously')),
    cfg.StrOpt('namespace', default='barbican',
               help=u._('Queue namespace')),
    cfg.StrOpt('topic', default='barbican.workers',
               help=u._('Queue topic name')),
    cfg.StrOpt('version', default='1.1',
               help=u._('Version of tasks invoked via queue')),
    cfg.StrOpt('server_name', default='barbican.queue',
               help=u._('Server name for RPC task processing server')),
]

# constant at one place if this needs to be changed later
KS_NOTIFICATIONS_GRP_NAME = 'keystone_notifications'

ks_queue_opt_group = cfg.OptGroup(name=KS_NOTIFICATIONS_GRP_NAME,
                                  title='Keystone Notification Options')

ks_queue_opts = [
    cfg.BoolOpt('enable', default=False,
                help=u._('True enables keystone notification listener '
                         ' functionality.')),
    cfg.StrOpt('control_exchange', default='openstack',
               help=u._('The default exchange under which topics are scoped. '
                        'May be overridden by an exchange name specified in '
                        ' the transport_url option.')),
    cfg.StrOpt('topic', default='notifications',
               help=u._("Keystone notification queue topic name. This name "
                        "needs to match one of values mentioned in Keystone "
                        "deployment\'s 'notification_topics' configuration "
                        "e.g."
                        "    notification_topics=notifications, "
                        "    barbican_notifications"
                        "Multiple servers may listen on a topic and messages "
                        " will be dispatched to one of the servers in a "
                        "round-robin fashion. That's why Barbican service "
                        " should have its own dedicated notification queue so "
                        " that it receives all of Keystone notifications.")),
    cfg.BoolOpt('allow_requeue', default=False,
                help=u._('True enables requeue feature in case of notification'
                         ' processing error. Enable this only when underlying '
                         'transport supports this feature.')),
    cfg.StrOpt('version', default='1.0',
               help=u._('Version of tasks invoked via notifications')),
    cfg.IntOpt('thread_pool_size', default=10,
               help=u._('Define the number of max threads to be used for '
                        'notification server processing functionality.')),
]

CONF = cfg.CONF
CONF.register_group(queue_opt_group)
CONF.register_opts(queue_opts, group=queue_opt_group)

CONF.register_group(ks_queue_opt_group)
CONF.register_opts(ks_queue_opts, group=ks_queue_opt_group)

TRANSPORT = None
IS_SERVER_SIDE = True

ALLOWED_EXMODS = [
    exception.__name__,
]


def get_allowed_exmods():
    return ALLOWED_EXMODS


def init(conf, is_server_side=True):
    global TRANSPORT, IS_SERVER_SIDE
    exmods = get_allowed_exmods()
    IS_SERVER_SIDE = is_server_side
    TRANSPORT = messaging.get_transport(conf,
                                        allowed_remote_exmods=exmods)


def is_server_side():
    return IS_SERVER_SIDE


def cleanup():
    global TRANSPORT
    assert TRANSPORT is not None
    TRANSPORT.cleanup()
    TRANSPORT = None


def get_target():
    return messaging.Target(topic=CONF.queue.topic,
                            namespace=CONF.queue.namespace,
                            version=CONF.queue.version,
                            server=CONF.queue.server_name)


def get_client(target=None, version_cap=None, serializer=None):
    if not CONF.queue.enable:
        return None

    assert TRANSPORT is not None
    queue_target = target or get_target()
    return messaging.RPCClient(TRANSPORT,
                               target=queue_target,
                               version_cap=version_cap,
                               serializer=serializer)


def get_server(target, endpoints, serializer=None):
    assert TRANSPORT is not None
    return messaging.get_rpc_server(TRANSPORT,
                                    target,
                                    endpoints,
                                    executor='eventlet',
                                    serializer=serializer)


def get_notification_target():
    conf_opts = getattr(CONF, KS_NOTIFICATIONS_GRP_NAME)
    return messaging.Target(exchange=conf_opts.control_exchange,
                            topic=conf_opts.topic,
                            version=conf_opts.version,
                            fanout=True)


def get_notification_server(targets, endpoints, serializer=None):
    """Retrieve notification server

    This Notification server uses same transport configuration as used by
    other barbican functionality like async order processing.

    Assumption is that messaging infrastructure is going to be shared (same)
    among different barbican features.
    """
    allow_requeue = getattr(getattr(CONF, KS_NOTIFICATIONS_GRP_NAME),
                            'allow_requeue')
    TRANSPORT._require_driver_features(requeue=allow_requeue)
    dispatcher = notfiy_dispatcher.NotificationDispatcher(targets, endpoints,
                                                          serializer,
                                                          allow_requeue)
    # we don't want blocking executor so use eventlet as executor choice
    return msg_server.MessageHandlingServer(TRANSPORT, dispatcher,
                                            executor='eventlet')
