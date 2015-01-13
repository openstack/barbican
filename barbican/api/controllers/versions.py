#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import pecan

from barbican.api import controllers
from barbican.common import utils
from barbican import i18n as u
from barbican import version

LOG = utils.getLogger(__name__)


class VersionController(object):

    def __init__(self):
        LOG.debug('=== Creating VersionController ===')

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Version retrieval'))
    def on_get(self):
        return {
            'v1': 'current',
            'build': version.__version__
        }
