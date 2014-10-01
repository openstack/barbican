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
API application handler for Cloudkeep's Barbican
"""
import json

import pecan
from webob import exc as webob_exc

try:
    import newrelic.agent
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo.config import cfg

from barbican.api.controllers import containers
from barbican.api.controllers import orders
from barbican.api.controllers import performance
from barbican.api.controllers import secrets
from barbican.api.controllers import transportkeys
from barbican.api.controllers import versions
from barbican.common import config
from barbican.model import repositories
from barbican.openstack.common import log
from barbican import queue

if newrelic_loaded:
    newrelic.agent.initialize('/etc/newrelic/newrelic.ini')


class JSONErrorHook(pecan.hooks.PecanHook):

    def on_error(self, state, exc):
        if isinstance(exc, webob_exc.HTTPError):
            exc.body = json.dumps({
                'code': exc.status_int,
                'title': exc.title,
                'description': exc.detail
            })
            state.response.content_type = "application/json"
            return exc.body


class PecanAPI(pecan.Pecan):

    # For performance testing only
    performance_uri = 'mu-1a90dfd0-7e7abba4-4e459908-fc097d60'
    performance_controller = performance.PerformanceController()

    def __init__(self, *args, **kwargs):
        hooks = [JSONErrorHook()]
        if kwargs.pop('is_transactional', None):
            transaction_hook = pecan.hooks.TransactionHook(
                repositories.start,
                repositories.start_read_only,
                repositories.commit,
                repositories.rollback,
                repositories.clear
            )
            hooks.append(transaction_hook)
        kwargs['hooks'] = hooks
        super(PecanAPI, self).__init__(*args, **kwargs)

    def route(self, req, node, path):
        # parse the first part of the URL. It could be the
        # resource name or the ID of the performance controller
        # example: /secrets
        parts = path.split('/')

        first_path = None
        if len(parts) > 1:
            first_path = parts[1]

        # Route to the special performance controller
        if first_path == self.performance_uri:
            return self.performance_controller.index, []

        controller, remainder = super(PecanAPI, self).route(req, node, path)

        return controller, remainder


def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application."""

    # Configure oslo logging and configuration services.
    config.parse_args()
    log.setup('barbican')
    config.setup_remote_pydev_debug()

    # Queuing initialization
    CONF = cfg.CONF
    queue.init(CONF, is_server_side=False)

    class RootController(object):
        secrets = secrets.SecretsController()
        orders = orders.OrdersController()
        containers = containers.ContainersController()
        transport_keys = transportkeys.TransportKeysController()

    wsgi_app = PecanAPI(
        RootController(), is_transactional=True, force_canonical=False)
    if newrelic_loaded:
        wsgi_app = newrelic.agent.WSGIApplicationWrapper(wsgi_app)
    return wsgi_app


def create_admin_app(global_config, **local_conf):
    config.parse_args()
    wsgi_app = pecan.make_app(versions.VersionController())
    return wsgi_app


create_version_app = create_admin_app
