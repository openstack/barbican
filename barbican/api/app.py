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

from barbican.api.controllers import (performance, orders, secrets, containers,
                                      transportkeys, versions)
from barbican.common import config
from barbican.crypto import extension_manager as ext
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
            return exc.body


class PecanAPI(pecan.Pecan):

    # For performance testing only
    performance_uri = 'mu-1a90dfd0-7e7abba4-4e459908-fc097d60'
    performance_controller = performance.PerformanceController()

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('hooks', []).append(JSONErrorHook())
        super(PecanAPI, self).__init__(*args, **kwargs)

    def route(self, req, node, path):
        # Pop the tenant ID from the path
        path = path.split('/')[1:]
        first_path = path.pop(0)

        # Route to the special performance controller
        if first_path == self.performance_uri:
            return self.performance_controller.index, []

        path = '/%s' % '/'.join(path)
        controller, remainder = super(PecanAPI, self).route(req, node, path)

        # Pass the tenant ID as the first argument to the controller
        remainder = list(remainder)
        remainder.insert(0, first_path)
        return controller, remainder


def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application"""

    # Configure oslo logging and configuration services.
    config.parse_args()
    log.setup('barbican')
    config.setup_remote_pydev_debug()
    # Crypto Plugin Manager
    crypto_mgr = ext.CryptoExtensionManager()

    # Queuing initialization
    CONF = cfg.CONF
    queue.init(CONF)

    class RootController(object):
        secrets = secrets.SecretsController(crypto_mgr)
        orders = orders.OrdersController()
        containers = containers.ContainersController()
        transport_keys = transportkeys.TransportKeysController()

    wsgi_app = PecanAPI(RootController(), force_canonical=False)
    if newrelic_loaded:
        wsgi_app = newrelic.agent.WSGIApplicationWrapper(wsgi_app)
    return wsgi_app


def create_admin_app(global_config, **local_conf):
    config.parse_args()
    wsgi_app = pecan.make_app(versions.VersionController())
    return wsgi_app


create_version_app = create_admin_app
