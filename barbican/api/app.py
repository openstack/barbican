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

import falcon

try:
    import newrelic.agent
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo.config import cfg

from barbican.api import resources as res
from barbican.common import config
from barbican.crypto import extension_manager as ext
from barbican.openstack.common import log
from barbican import queue

if newrelic_loaded:
    newrelic.agent.initialize('/etc/newrelic/newrelic.ini')


def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application"""

    # Configure oslo logging and configuration services.
    config.parse_args()
    log.setup('barbican')

    # Crypto Plugin Manager
    crypto_mgr = ext.CryptoExtensionManager()

    # Queuing initialization
    CONF = cfg.CONF
    queue.init(CONF)

    # Resources
    versions = res.VersionResource()
    secrets = res.SecretsResource(crypto_mgr)
    secret = res.SecretResource(crypto_mgr)
    orders = res.OrdersResource()
    order = res.OrderResource()
    verifications = res.VerificationsResource()
    verification = res.VerificationResource()

    # For performance testing only
    performance = res.PerformanceResource()
    performance_uri = 'mu-1a90dfd0-7e7abba4-4e459908-fc097d60'

    wsgi_app = api = falcon.API()
    if newrelic_loaded:
        wsgi_app = newrelic.agent.WSGIApplicationWrapper(wsgi_app)

    api.add_route('/', versions)
    api.add_route('/v1/{keystone_id}/secrets', secrets)
    api.add_route('/v1/{keystone_id}/secrets/{secret_id}', secret)
    api.add_route('/v1/{keystone_id}/orders', orders)
    api.add_route('/v1/{keystone_id}/orders/{order_id}', order)
    api.add_route('/v1/{keystone_id}/verifications', verifications)
    api.add_route('/v1/{keystone_id}/verifications/{verification_id}',
                  verification)

    # For performance testing only
    api.add_route('/{0}'.format(performance_uri), performance)

    return wsgi_app


def create_admin_app(global_config, **local_conf):
    config.parse_args()

    versions = res.VersionResource()
    wsgi_app = api = falcon.API()
    api.add_route('/', versions)

    return wsgi_app
