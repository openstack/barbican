# Copyright (c) 2015 Cisco Systems
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


from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)
UNLIMITED_VALUE = -1


quota_opt_group = cfg.OptGroup(name='quotas',
                               title='Quota Options')

quota_opts = [
    cfg.BoolOpt('enabled',
                default=False,
                help='When True, quotas are enforced.'),
    cfg.IntOpt('quota_secrets',
               default=500,
               help='Number of secrets allowed per project'),
    cfg.IntOpt('quota_orders',
               default=100,
               help='Number of orders allowed per project'),
    cfg.IntOpt('quota_containers',
               default=-1,
               help='Number of containers allowed per project'),
    cfg.IntOpt('quota_transport_keys',
               default=100,
               help='Number of transport keys allowed per project'),
    cfg.IntOpt('quota_consumers',
               default=100,
               help='Number of consumers allowed per project'),
]

CONF = cfg.CONF
CONF.register_group(quota_opt_group)
CONF.register_opts(quota_opts, group=quota_opt_group)


class QuotaDriver(object):
    """Driver to enforce quotas and obtain quota information."""

    def get_defaults(self):
        """Return list of default quotas"""
        quotas = {
            'secrets': CONF.quotas.quota_secrets,
            'orders': CONF.quotas.quota_orders,
            'containers': CONF.quotas.quota_containers,
            'transport_keys': CONF.quotas.quota_transport_keys,
            'consumers': CONF.quotas.quota_consumers
        }
        return quotas

    def _is_unlimited_value(self, v):
        """A helper method to check for unlimited value."""

        return v <= UNLIMITED_VALUE
