# Copyright (c) 2013-2015 Rackspace, Inc.
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
API application handler for Cloudkeep's Barbican
"""
import pecan

try:
    import newrelic.agent
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo_config import cfg
from oslo_log import log

from barbican.api.controllers import containers
from barbican.api.controllers import orders
from barbican.api.controllers import secrets
from barbican.api.controllers import transportkeys
from barbican.api.controllers import versions
from barbican.api import hooks
from barbican.common import config
from barbican.model import repositories
from barbican import queue

if newrelic_loaded:
    newrelic.agent.initialize('/etc/newrelic/newrelic.ini')


class RootController(object):
    secrets = secrets.SecretsController()
    orders = orders.OrdersController()
    containers = containers.ContainersController()
    transport_keys = transportkeys.TransportKeysController()


def build_wsgi_app(controller=None, transactional=False):
    """WSGI application creation helper

    :param controller: Overrides default application controller
    :param transactional: Adds transaction hook for all requests
    """
    request_hooks = [hooks.JSONErrorHook()]
    if transactional:
        request_hooks.append(hooks.BarbicanTransactionHook())

    # Create WSGI app
    wsgi_app = pecan.Pecan(
        controller or RootController(),
        hooks=request_hooks,
        force_canonical=False
    )
    return wsgi_app


def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application."""

    # Queuing initialization
    CONF = cfg.CONF
    queue.init(CONF, is_server_side=False)

    # Configure oslo logging and configuration services.
    config.parse_args()
    log.setup(CONF, 'barbican')
    config.setup_remote_pydev_debug()

    # Initializing the database engine and session factory before the app
    # starts ensures we don't lose requests due to lazy initialiation of db
    # connections.
    repositories.setup_database_engine_and_factory()

    # Setup app with transactional hook enabled
    wsgi_app = build_wsgi_app(transactional=True)

    if newrelic_loaded:
        wsgi_app = newrelic.agent.WSGIApplicationWrapper(wsgi_app)
    return wsgi_app


def create_admin_app(global_config, **local_conf):
    config.parse_args()
    wsgi_app = pecan.make_app(versions.VersionController())
    return wsgi_app


create_version_app = create_admin_app
