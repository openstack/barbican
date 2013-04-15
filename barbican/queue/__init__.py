# Copyright (c) 2013 Rackspace, Inc.
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
from barbican.common import config
from barbican.openstack.common.gettextutils import _

queue_opts = [
    cfg.StrOpt('queue_api', default='barbican.queue.simple',
               help=_('Python module path of queue implementation API')),
]

CONF = cfg.CONF
CONF.register_opts(queue_opts, group='queue')
