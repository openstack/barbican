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
Queue objects for Barbican
"""
import oslo_messaging as messaging
from oslo_messaging.notify import dispatcher as notify_dispatcher
from oslo_messaging import server as msg_server

from barbican.common import config
from barbican.common import exception
from barbican.common import utils


LOG = utils.getLogger(__name__)

# Constant at one place if this needs to be changed later
KS_NOTIFICATIONS_GRP_NAME = config.KS_NOTIFICATIONS_GRP_NAME

CONF = config.CONF

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
    TRANSPORT = messaging.get_transport(conf, allowed_remote_exmods=exmods)


def is_server_side():
    return IS_SERVER_SIDE


def cleanup():
    global TRANSPORT
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

    queue_target = target or get_target()
    return messaging.RPCClient(TRANSPORT,
                               target=queue_target,
                               version_cap=version_cap,
                               serializer=serializer)


def get_server(target, endpoints, serializer=None):
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
    dispatcher = notify_dispatcher.NotificationDispatcher(targets, endpoints,
                                                          serializer,
                                                          allow_requeue)
    # we don't want blocking executor so use eventlet as executor choice
    return msg_server.MessageHandlingServer(TRANSPORT, dispatcher,
                                            executor='eventlet')
