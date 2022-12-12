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
from urllib import parse

from barbican.api import controllers
from barbican.api.controllers import containers
from barbican.api.controllers import orders
from barbican.api.controllers import quotas
from barbican.api.controllers import secrets
from barbican.api.controllers import secretstores
from barbican.api.controllers import transportkeys
from barbican.common import utils
from barbican import i18n as u
from barbican import version

LOG = utils.getLogger(__name__)

_MIN_MICROVERSION = 0
_MAX_MICROVERSION = 1
_LAST_UPDATED = '2021-02-10T00:00:00Z'

# NOTE(xek): The above defines the minimum and maximum version of the API
# across all of the v1 REST API.
# When introducing a new microversion, the _MAX_MICROVERSION
# needs to be incremented by 1 and the _LAST_UPDATED string updated.
# Additionally, the new microversion has to be documented in
# doc/source/api/microversion_history.rst
#
# The following is the complete (ordered) list of supported versions
# used by the microversion middleware to parse what is allowed and
# supported.

VERSIONS = ['1.{}'.format(v) for v in range(_MIN_MICROVERSION,
                                            _MAX_MICROVERSION + 1)]
MIN_API_VERSION = VERSIONS[0]
MAX_API_VERSION = VERSIONS[-1]

MIME_TYPE_JSON = 'application/json'
MIME_TYPE_JSON_HOME = 'application/json-home'
MEDIA_TYPE_JSON = 'application/vnd.openstack.key-manager-%s+json'


def is_supported(req, min_version=MIN_API_VERSION,
                 max_version=MAX_API_VERSION):
    """Check if API request version satisfies version restrictions.

    :param req: request object
    :param min_version: minimal version of API needed for correct
           request processing
    :param max_version: maximum version of API needed for correct
           request processing

    :returns: True if request satisfies minimal and maximum API version
             requirements. False in other case.
    """
    requested_version = str(req.environ.get('key-manager.microversion',
                                            MIN_API_VERSION))

    return (VERSIONS.index(max_version) >=
            VERSIONS.index(requested_version) >=
            VERSIONS.index(min_version))


def _version_not_found():
    """Throw exception indicating version not found."""
    pecan.abort(404, u._("The version you requested wasn't found"))


def _get_versioned_url(version):
    if version[-1] != '/':
        version += '/'
    # If host_href is not set in barbican conf, then derive it from request url
    host_part = utils.get_base_url_from_request()
    if host_part[-1] != '/':
        host_part += '/'
    return parse.urljoin(host_part, version)


class BaseVersionController(object):
    """Base class for the version-specific controllers"""

    @classmethod
    def get_version_info(cls, microversion_spec=True):
        version = {
            'id': cls.version_id,
            'status': 'CURRENT',
            'min_version': cls.min_version,
            'max_version': cls.version,
            'links': [
                {
                    'rel': 'self',
                    'href': _get_versioned_url(cls.version_string),
                },
                {
                    'rel': 'describedby',
                    'type': 'text/html',
                    'href': 'https://docs.openstack.org/'
                }
            ],
        }
        if not microversion_spec:
            version.pop('min_version')
            version.pop('max_version')
            version['status'] = 'stable'
            version['updated']: cls.last_updated
            version['media-types'] = [
                {
                    'base': MIME_TYPE_JSON,
                    'type': MEDIA_TYPE_JSON % cls.version_string
                }
            ]
        return version


class V1Controller(BaseVersionController):
    """Root controller for the v1 API"""

    version_string = 'v1'

    # NOTE(jaosorior): We might start using decimals in the future, meanwhile
    # this is the same as the version string.
    version_id = 'v1'

    version = MAX_API_VERSION
    min_version = MIN_API_VERSION
    last_updated = _LAST_UPDATED

    def __init__(self):
        LOG.debug('=== Creating V1Controller ===')
        self.secrets = secrets.SecretsController()
        self.orders = orders.OrdersController()
        self.containers = containers.ContainersController()
        self.transport_keys = transportkeys.TransportKeysController()
        self.quotas = quotas.QuotasController()
        setattr(self, 'project-quotas', quotas.ProjectsQuotasController())
        setattr(self, 'secret-stores', secretstores.SecretStoresController())

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @utils.allow_certain_content_types(MIME_TYPE_JSON, MIME_TYPE_JSON_HOME)
    @controllers.handle_exceptions(u._('Version retrieval'))
    def on_get(self):
        pecan.core.override_template('json')
        if is_supported(pecan.request, max_version='1.0'):
            return {'version': self.get_version_info(microversion_spec=False)}
        else:
            return {'version': self.get_version_info()}


AVAILABLE_VERSIONS = {
    V1Controller.version_string: V1Controller,
}

DEFAULT_VERSION = V1Controller.version_string


class VersionsController(object):

    def __init__(self):
        LOG.debug('=== Creating VersionsController ===')

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @utils.allow_certain_content_types(MIME_TYPE_JSON, MIME_TYPE_JSON_HOME)
    def on_get(self, **kwargs):
        """The list of versions is dependent on the context."""
        self._redirect_to_default_json_home_if_needed(pecan.request)

        if 'build' in kwargs:
            return {'build': version.__version__}

        if is_supported(pecan.request, max_version='1.0'):
            resp = {
                'versions': {
                    'values': [
                        V1Controller.get_version_info(microversion_spec=False)
                    ]
                }
            }
        else:
            resp = {
                'versions': [
                    version_cls.get_version_info() for version_cls in
                    AVAILABLE_VERSIONS.values()]
            }

        # Since we are returning all the versions available, the proper status
        # code is Multiple Choices (300)
        pecan.response.status = 300
        return resp

    def _redirect_to_default_json_home_if_needed(self, request):
        if self._mime_best_match(request.accept) == MIME_TYPE_JSON_HOME:
            url = _get_versioned_url(DEFAULT_VERSION)
            LOG.debug("Redirecting Request to " + url)
            # NOTE(jaosorior): This issues an "external" redirect because of
            # two reasons:
            # * This module doesn't require authorization, and accessing
            #   specific version info needs that.
            # * The resource is a separate app_factory and won't be found
            #   internally
            pecan.redirect(url, request=request)

    def _mime_best_match(self, accept):
        if not accept:
            return MIME_TYPE_JSON

        SUPPORTED_TYPES = [MIME_TYPE_JSON, MIME_TYPE_JSON_HOME]
        return accept.best_match(SUPPORTED_TYPES)
