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
Configuration setup for Barbican.
"""

import logging
import os

from oslo_config import cfg
from oslo_log import log
from oslo_middleware import cors
from oslo_service import _options

from barbican import i18n as u
import barbican.version

MAX_BYTES_REQUEST_INPUT_ACCEPTED = 15000
DEFAULT_MAX_SECRET_BYTES = 10000
KS_NOTIFICATIONS_GRP_NAME = 'keystone_notifications'

context_opts = [
    cfg.StrOpt('admin_role', default='admin',
               help=u._('Role used to identify an authenticated user as '
                        'administrator.')),
    cfg.BoolOpt('allow_anonymous_access', default=False,
                help=u._('Allow unauthenticated users to access the API with '
                         'read-only privileges. This only applies when using '
                         'ContextMiddleware.')),
]

common_opts = [
    cfg.IntOpt('max_allowed_request_size_in_bytes',
               default=MAX_BYTES_REQUEST_INPUT_ACCEPTED),
    cfg.IntOpt('max_allowed_secret_in_bytes',
               default=DEFAULT_MAX_SECRET_BYTES),
]

host_opts = [
    cfg.StrOpt('host_href', default='http://localhost:9311'),
]

db_opts = [
    cfg.StrOpt('sql_connection'),
    cfg.IntOpt('sql_idle_timeout', default=3600),
    cfg.IntOpt('sql_max_retries', default=60),
    cfg.IntOpt('sql_retry_interval', default=1),
    cfg.BoolOpt('db_auto_create', default=True),
    cfg.IntOpt('max_limit_paging', default=100),
    cfg.IntOpt('default_limit_paging', default=10),
    cfg.StrOpt('sql_pool_class'),
    cfg.BoolOpt('sql_pool_logging', default=False),
    cfg.IntOpt('sql_pool_size'),
    cfg.IntOpt('sql_pool_max_overflow'),
]

retry_opt_group = cfg.OptGroup(name='retry_scheduler',
                               title='Retry/Scheduler Options')

retry_opts = [
    cfg.FloatOpt(
        'initial_delay_seconds', default=10.0,
        help=u._('Seconds (float) to wait before starting retry scheduler')),
    cfg.FloatOpt(
        'periodic_interval_max_seconds', default=10.0,
        help=u._('Seconds (float) to wait between periodic schedule events')),
]

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
    cfg.IntOpt('asynchronous_workers', default=1,
               help=u._('Number of asynchronous worker processes')),
]

ks_queue_opt_group = cfg.OptGroup(name=KS_NOTIFICATIONS_GRP_NAME,
                                  title='Keystone Notification Options')

ks_queue_opts = [
    cfg.BoolOpt('enable', default=False,
                help=u._('True enables keystone notification listener '
                         ' functionality.')),
    cfg.StrOpt('control_exchange', default='openstack',
               help=u._('The default exchange under which topics are scoped. '
                        'May be overridden by an exchange name specified in '
                        'the transport_url option.')),
    cfg.StrOpt('topic', default='notifications',
               help=u._("Keystone notification queue topic name. This name "
                        "needs to match one of values mentioned in Keystone "
                        "deployment's 'notification_topics' configuration "
                        "e.g."
                        "    notification_topics=notifications, "
                        "    barbican_notifications"
                        "Multiple servers may listen on a topic and messages "
                        "will be dispatched to one of the servers in a "
                        "round-robin fashion. That's why Barbican service "
                        "should have its own dedicated notification queue so "
                        "that it receives all of Keystone notifications.")),
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

quota_opt_group = cfg.OptGroup(name='quotas',
                               title='Quota Options')

quota_opts = [
    cfg.IntOpt('quota_secrets',
               default=-1,
               help='Number of secrets allowed per project'),
    cfg.IntOpt('quota_orders',
               default=-1,
               help='Number of orders allowed per project'),
    cfg.IntOpt('quota_containers',
               default=-1,
               help='Number of containers allowed per project'),
    cfg.IntOpt('quota_consumers',
               default=-1,
               help='Number of consumers allowed per project'),
    cfg.IntOpt('quota_cas',
               default=-1,
               help='Number of CAs allowed per project')
]

# Flag to indicate barbican configuration is already parsed once or not
_CONFIG_PARSED_ONCE = False


def parse_args(conf, args=None, usage=None, default_config_files=None):
    global _CONFIG_PARSED_ONCE
    conf(args=args if args else [],
         project='barbican',
         prog='barbican',
         version=barbican.version.__version__,
         usage=usage,
         default_config_files=default_config_files)

    conf.pydev_debug_host = os.environ.get('PYDEV_DEBUG_HOST')
    conf.pydev_debug_port = os.environ.get('PYDEV_DEBUG_PORT')

    # Assign cfg.CONF handle to parsed barbican configuration once at startup
    # only. No need to keep re-assigning it with separate plugin conf usage
    if not _CONFIG_PARSED_ONCE:
        cfg.CONF = conf
        _CONFIG_PARSED_ONCE = True


def new_config():
    conf = cfg.ConfigOpts()
    log.register_options(conf)
    conf.register_opts(context_opts)
    conf.register_opts(common_opts)
    conf.register_opts(host_opts)
    conf.register_opts(db_opts)
    conf.register_opts(_options.eventlet_backdoor_opts)
    conf.register_opts(_options.periodic_opts)

    conf.register_opts(_options.ssl_opts, "ssl")

    conf.register_group(retry_opt_group)
    conf.register_opts(retry_opts, group=retry_opt_group)

    conf.register_group(queue_opt_group)
    conf.register_opts(queue_opts, group=queue_opt_group)

    conf.register_group(ks_queue_opt_group)
    conf.register_opts(ks_queue_opts, group=ks_queue_opt_group)

    conf.register_group(quota_opt_group)
    conf.register_opts(quota_opts, group=quota_opt_group)

    # Update default values from libraries that carry their own oslo.config
    # initialization and configuration.
    set_middleware_defaults()

    return conf


def setup_remote_pydev_debug():
    """Required setup for remote debugging."""

    if CONF.pydev_debug_host and CONF.pydev_debug_port:
        try:
            try:
                from pydev import pydevd
            except ImportError:
                import pydevd

            pydevd.settrace(CONF.pydev_debug_host,
                            port=int(CONF.pydev_debug_port),
                            stdoutToServer=True,
                            stderrToServer=True)
        except Exception:
            LOG.exception('Unable to join debugger, please '
                          'make sure that the debugger processes is '
                          'listening on debug-host \'%s\' debug-port \'%s\'.',
                          CONF.pydev_debug_host, CONF.pydev_debug_port)
            raise


def set_middleware_defaults():
    """Update default configuration options for oslo.middleware."""
    # CORS Defaults
    # TODO(krotscheck): Update with https://review.openstack.org/#/c/285368/
    cfg.set_defaults(cors.CORS_OPTS,
                     allow_headers=['X-Auth-Token',
                                    'X-Openstack-Request-Id',
                                    'X-Project-Id',
                                    'X-Identity-Status',
                                    'X-User-Id',
                                    'X-Storage-Token',
                                    'X-Domain-Id',
                                    'X-User-Domain-Id',
                                    'X-Project-Domain-Id',
                                    'X-Roles'],
                     expose_headers=['X-Auth-Token',
                                     'X-Openstack-Request-Id',
                                     'X-Project-Id',
                                     'X-Identity-Status',
                                     'X-User-Id',
                                     'X-Storage-Token',
                                     'X-Domain-Id',
                                     'X-User-Domain-Id',
                                     'X-Project-Domain-Id',
                                     'X-Roles'],
                     allow_methods=['GET',
                                    'PUT',
                                    'POST',
                                    'DELETE',
                                    'PATCH']
                     )

CONF = new_config()
LOG = logging.getLogger(__name__)
parse_args(CONF)
