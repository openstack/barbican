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

import mimetypes
import urllib

import pecan

from barbican import api
from barbican.api import controllers
from barbican.api.controllers import hrefs
from barbican.common import exception
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican.model import repositories as repo
from barbican.openstack.common import gettextutils as u
from barbican.plugin import resources as plugin
from barbican.plugin import util as putil


LOG = utils.getLogger(__name__)


def allow_all_content_types(f):
    cfg = pecan.util._cfg(f)
    cfg.setdefault('content_types', {})
    cfg['content_types'].update((value, '')
                                for value in mimetypes.types_map.values())
    return f


def _secret_not_found():
    """Throw exception indicating secret not found."""
    pecan.abort(404, u._('Not Found. Sorry but your secret is in '
                         'another castle.'))


def _secret_already_has_data():
    """Throw exception that the secret already has data."""
    pecan.abort(409, u._("Secret already has data, cannot modify it."))


class SecretController(object):
    """Handles Secret retrieval and deletion requests."""

    def __init__(self, secret_id,
                 tenant_repo=None, secret_repo=None, datum_repo=None,
                 kek_repo=None, secret_meta_repo=None):
        LOG.debug('=== Creating SecretController ===')
        self.secret_id = secret_id

        #TODO(john-wood-w) Remove passed-in repositories in favor of
        #  repository factories and patches in unit tests.
        self.repos = repo.Repositories(tenant_repo=tenant_repo,
                                       secret_repo=secret_repo,
                                       datum_repo=datum_repo,
                                       kek_repo=kek_repo,
                                       secret_meta_repo=secret_meta_repo)

    @pecan.expose(generic=True)
    @allow_all_content_types
    @controllers.handle_exceptions(u._('Secret retrieval'))
    @controllers.enforce_rbac('secret:get')
    def index(self, keystone_id):

        secret = self.repos.secret_repo.get(entity_id=self.secret_id,
                                            keystone_id=keystone_id,
                                            suppress_exception=True)
        if not secret:
            _secret_not_found()

        if controllers.is_json_request_accept(pecan.request):
            # Metadata-only response, no secret retrieval is necessary.
            pecan.override_template('json', 'application/json')
            secret_fields = putil.mime_types.augment_fields_with_content_types(
                secret)
            return hrefs.convert_to_hrefs(keystone_id, secret_fields)
        else:
            tenant = res.get_or_create_tenant(keystone_id,
                                              self.repos.tenant_repo)
            pecan.override_template('', pecan.request.accept.header_value)

            return plugin.get_secret(pecan.request.accept.header_value,
                                     secret,
                                     tenant)

    @index.when(method='PUT')
    @allow_all_content_types
    @controllers.handle_exceptions(u._('Secret update'))
    @controllers.enforce_rbac('secret:put')
    @controllers.enforce_content_types(['application/octet-stream',
                                       'text/plain'])
    def on_put(self, keystone_id, **kwargs):

        if not pecan.request.content_type or \
                pecan.request.content_type == 'application/json':
            pecan.abort(
                415,
                u._("Content-Type of '{0}' is not supported for PUT.").format(
                    pecan.request.content_type
                )
            )

        payload = pecan.request.body
        if not payload:
            raise exception.NoDataToProcess()
        if validators.secret_too_big(payload):
            raise exception.LimitExceeded()

        secret_model = self.repos.secret_repo.get(entity_id=self.secret_id,
                                                  keystone_id=keystone_id,
                                                  suppress_exception=True)
        if not secret_model:
            _secret_not_found()

        if secret_model.encrypted_data:
            _secret_already_has_data()

        tenant_model = res.get_or_create_tenant(keystone_id,
                                                self.repos.tenant_repo)
        content_type = pecan.request.content_type
        content_encoding = pecan.request.headers.get('Content-Encoding')

        plugin.store_secret(payload, content_type,
                            content_encoding, secret_model.to_dict_fields(),
                            secret_model, tenant_model, self.repos)

    @index.when(method='DELETE')
    @controllers.handle_exceptions(u._('Secret deletion'))
    @controllers.enforce_rbac('secret:delete')
    def on_delete(self, keystone_id, **kwargs):

        secret_model = self.repos.secret_repo.get(entity_id=self.secret_id,
                                                  keystone_id=keystone_id,
                                                  suppress_exception=True)
        if not secret_model:
            _secret_not_found()

        plugin.delete_secret(secret_model, keystone_id, self.repos)


class SecretsController(object):
    """Handles Secret creation requests."""

    def __init__(self,
                 tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None, kek_repo=None,
                 secret_meta_repo=None):
        LOG.debug('Creating SecretsController')
        self.validator = validators.NewSecretValidator()
        self.repos = repo.Repositories(tenant_repo=tenant_repo,
                                       tenant_secret_repo=tenant_secret_repo,
                                       secret_repo=secret_repo,
                                       datum_repo=datum_repo,
                                       kek_repo=kek_repo,
                                       secret_meta_repo=secret_meta_repo)

    @pecan.expose()
    def _lookup(self, secret_id, *remainder):
        return SecretController(secret_id,
                                self.repos.tenant_repo,
                                self.repos.secret_repo,
                                self.repos.datum_repo,
                                self.repos.kek_repo,
                                self.repos.secret_meta_repo), remainder

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Secret(s) retrieval'))
    @controllers.enforce_rbac('secrets:get')
    def index(self, keystone_id, **kw):
        LOG.debug('Start secrets on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        name = kw.get('name', '')
        if name:
            name = urllib.unquote_plus(name)

        bits = kw.get('bits', 0)
        try:
            bits = int(bits)
        except ValueError:
            # as per Github issue 171, if bits is invalid then
            # the default should be used.
            bits = 0

        result = self.repos.secret_repo.get_by_create_date(
            keystone_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
            name=name,
            alg=kw.get('alg'),
            mode=kw.get('mode'),
            bits=bits,
            suppress_exception=True
        )

        secrets, offset, limit, total = result

        if not secrets:
            secrets_resp_overall = {'secrets': [],
                                    'total': total}
        else:
            secret_fields = lambda sf: putil.mime_types\
                .augment_fields_with_content_types(sf)
            secrets_resp = [
                hrefs.convert_to_hrefs(keystone_id, secret_fields(s))
                for s in secrets
            ]
            secrets_resp_overall = hrefs.add_nav_hrefs(
                'secrets', keystone_id, offset, limit, total,
                {'secrets': secrets_resp}
            )
            secrets_resp_overall.update({'total': total})

        return secrets_resp_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Secret creation'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, keystone_id, **kwargs):
        LOG.debug('Start on_post for tenant-ID {0}:...'.format(keystone_id))

        data = api.load_body(pecan.request, validator=self.validator)
        tenant = res.get_or_create_tenant(keystone_id, self.repos.tenant_repo)

        new_secret = plugin.store_secret(data.get('payload'),
                                         data.get('payload_content_type',
                                                  'application/octet-stream'),
                                         data.get('payload_content_encoding'),
                                         data, None, tenant,
                                         self.repos)

        pecan.response.status = 201
        pecan.response.headers['Location'] = '/{0}/secrets/{1}'.format(
            keystone_id, new_secret.id
        )
        url = hrefs.convert_secret_to_href(keystone_id, new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        return {'secret_ref': url}
