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
from oslo_policy import opts as policy_opts
from oslo_service import _options

from barbican import i18n as u
import barbican.version

MAX_BYTES_REQUEST_INPUT_ACCEPTED = 25000
DEFAULT_MAX_SECRET_BYTES = 20000
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
               default=MAX_BYTES_REQUEST_INPUT_ACCEPTED,
               help=u._("Maximum allowed http request size against the "
                        "barbican-api.")),
    cfg.IntOpt('max_allowed_secret_in_bytes',
               default=DEFAULT_MAX_SECRET_BYTES,
               help=u._("Maximum allowed secret size in bytes.")),
]

host_opts = [
    cfg.StrOpt('host_href', default='http://localhost:9311',
               help=u._("Host name, for use in HATEOAS-style references Note: "
                        "Typically this would be the load balanced endpoint "
                        "that clients would use to communicate back with this "
                        "service. If a deployment wants to derive host from "
                        "wsgi request instead then make this blank. Blank is "
                        "needed to override default config value which is "
                        "'http://localhost:9311'")),
]

db_opts = [
    cfg.StrOpt('sql_connection',
               default="sqlite:///barbican.sqlite",
               secret=True,
               help=u._("SQLAlchemy connection string for the reference "
                        "implementation registry server. Any valid "
                        "SQLAlchemy connection string is fine. See: "
                        "http://www.sqlalchemy.org/docs/05/reference/"
                        "sqlalchemy/connections.html#sqlalchemy."
                        "create_engine. Note: For absolute addresses, use "
                        "'////' slashes after 'sqlite:'.")),
    cfg.IntOpt('sql_idle_timeout', default=3600,
               help=u._("Period in seconds after which SQLAlchemy should "
                        "reestablish its connection to the database. MySQL "
                        "uses a default `wait_timeout` of 8 hours, after "
                        "which it will drop idle connections. This can result "
                        "in 'MySQL Gone Away' exceptions. If you notice this, "
                        "you can lower this value to ensure that SQLAlchemy "
                        "reconnects before MySQL can drop the connection.")),
    cfg.IntOpt('sql_max_retries', default=60,
               help=u._("Maximum number of database connection retries "
                        "during startup. Set to -1 to specify an infinite "
                        "retry count.")),
    cfg.IntOpt('sql_retry_interval', default=1,
               help=u._("Interval between retries of opening a SQL "
                        "connection.")),
    cfg.BoolOpt('db_auto_create', default=False,
                help=u._("Create the Barbican database on service startup.")),
    cfg.IntOpt('max_limit_paging', default=100,
               help=u._("Maximum page size for the 'limit' paging URL "
                        "parameter.")),
    cfg.IntOpt('default_limit_paging', default=10,
               help=u._("Default page size for the 'limit' paging URL "
                        "parameter.")),
    cfg.StrOpt('sql_pool_class', default="QueuePool",
               help=u._("Accepts a class imported from the sqlalchemy.pool "
                        "module, and handles the details of building the "
                        "pool for you. If commented out, SQLAlchemy will "
                        "select based on the database dialect. Other options "
                        "are QueuePool (for SQLAlchemy-managed connections) "
                        "and NullPool (to disabled SQLAlchemy management of "
                        "connections). See http://docs.sqlalchemy.org/en/"
                        "latest/core/pooling.html for more details")),
    cfg.BoolOpt('sql_pool_logging', default=False,
                help=u._("Show SQLAlchemy pool-related debugging output in "
                         "logs (sets DEBUG log level output) if specified.")),
    cfg.IntOpt('sql_pool_size', default=5,
               help=u._("Size of pool used by SQLAlchemy. This is the largest "
                        "number of connections that will be kept persistently "
                        "in the pool. Can be set to 0 to indicate no size "
                        "limit. To disable pooling, use a NullPool with "
                        "sql_pool_class instead. Comment out to allow "
                        "SQLAlchemy to select the default.")),
    cfg.IntOpt('sql_pool_max_overflow', default=10,
               help=u._("# The maximum overflow size of the pool used by "
                        "SQLAlchemy. When the number of checked-out "
                        "connections reaches the size set in sql_pool_size, "
                        "additional connections will be returned up to this "
                        "limit. It follows then that the total number of "
                        "simultaneous connections the pool will allow is "
                        "sql_pool_size + sql_pool_max_overflow. Can be set "
                        "to -1 to indicate no overflow limit, so no limit "
                        "will be placed on the total number of concurrent "
                        "connections. Comment out to allow SQLAlchemy to "
                        "select the default.")),
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
    cfg.StrOpt('control_exchange', default='keystone',
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
                        "that it receives all of Keystone notifications. "
                        "Alternatively if the chosen oslo.messaging backend "
                        "supports listener pooling (for example rabbitmq), "
                        "setting a non-default 'pool_name' option "
                        "should be preferred.")),
    cfg.StrOpt('pool_name',
               help=u._("Pool name for notifications listener. "
                        "Setting this to a distinctive value will allow "
                        "barbican notifications listener to receive its own "
                        "copy of all messages from the topic without "
                        "without interfering with other services listening "
                        "on the same topic. This feature is supported only "
                        "by some oslo.messaging backends "
                        "(in particilar by rabbitmq) and for those it is "
                        "preferrable to use it instead of separate "
                        "notification topic for barbican.")),
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
               help=u._('Number of secrets allowed per project')),
    cfg.IntOpt('quota_orders',
               default=-1,
               help=u._('Number of orders allowed per project')),
    cfg.IntOpt('quota_containers',
               default=-1,
               help=u._('Number of containers allowed per project')),
    cfg.IntOpt('quota_consumers',
               default=-1,
               help=u._('Number of consumers allowed per project')),
    cfg.IntOpt('quota_cas',
               default=-1,
               help=u._('Number of CAs allowed per project'))
]


def list_opts():
    yield None, context_opts
    yield None, common_opts
    yield None, host_opts
    yield None, db_opts
    yield None, _options.eventlet_backdoor_opts
    yield retry_opt_group, retry_opts
    yield queue_opt_group, queue_opts
    yield ks_queue_opt_group, ks_queue_opts
    yield quota_opt_group, quota_opts


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
                          'listening on debug-host \'%(debug-host)s\' '
                          'debug-port \'%(debug-port)s\'.',
                          {'debug-host': CONF.pydev_debug_host,
                           'debug-port': CONF.pydev_debug_port})
            raise


def set_lib_defaults():
    """Update default value for configuration options from other namespace.

    Example, oslo lib config options. This is needed for
    config generator tool to pick these default value changes.
    https://docs.openstack.org/oslo.config/latest/cli/
    generator.html#modifying-defaults-from-other-namespaces
    """

    set_middleware_defaults()

    # TODO(gmann): Remove setting the default value of config policy_file
    # once oslo_policy change the default value to 'policy.yaml'.
    # https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
    DEFAULT_POLICY_FILE = 'policy.yaml'
    policy_opts.set_defaults(CONF, DEFAULT_POLICY_FILE)


def set_middleware_defaults():
    """Update default configuration options for oslo.middleware."""
    cors.set_defaults(
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

# Adding global scope dict for all different configs created in various
# modules. In barbican, each plugin module creates its own *new* config
# instance so its error prone to share/access config values across modules
# as these module imports introduce a cyclic dependency. To avoid this, each
# plugin can set this dict after its own config instance is created and parsed.
_CONFIGS = {}


def set_module_config(name, module_conf):
    """Each plugin can set its own conf instance with its group name."""
    _CONFIGS[name] = module_conf


def get_module_config(name):
    """Get handle to plugin specific config instance by its group name."""
    return _CONFIGS[name]
