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
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import repositories as repo
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


def _request_has_twsk_but_no_transport_key_id():
    """Throw exception for bad wrapping parameters.

    Throw exception if transport key wrapped session key has been provided,
    but the transport key id has not.
    """
    pecan.abort(400, u._('Transport key wrapped session key has been '
                         'provided to wrap secrets for retrieval, but the '
                         'transport key id has not been provided.'))


class SecretController(object):
    """Handles Secret retrieval and deletion requests."""

    def __init__(self, secret,
                 project_repo=None, secret_repo=None, datum_repo=None,
                 kek_repo=None, secret_meta_repo=None,
                 transport_key_repo=None):
        LOG.debug('=== Creating SecretController ===')
        self.secret = secret

        # TODO(john-wood-w) Remove passed-in repositories in favor of
        #  repository factories and patches in unit tests.
        self.repos = repo.Repositories(project_repo=project_repo,
                                       secret_repo=secret_repo,
                                       datum_repo=datum_repo,
                                       kek_repo=kek_repo,
                                       secret_meta_repo=secret_meta_repo,
                                       transport_key_repo=transport_key_repo)

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET')
    @allow_all_content_types
    @controllers.handle_exceptions(u._('Secret retrieval'))
    @controllers.enforce_rbac('secret:get')
    def on_get(self, external_project_id, **kwargs):
        if controllers.is_json_request_accept(pecan.request):
            return self._on_get_secret_metadata(self.secret, **kwargs)
        else:
            return self._on_get_secret_payload(self.secret,
                                               external_project_id,
                                               **kwargs)

    def _on_get_secret_metadata(self, secret, **kwargs):
        """GET Metadata-only for a secret."""
        pecan.override_template('json', 'application/json')

        secret_fields = putil.mime_types.augment_fields_with_content_types(
            secret)

        transport_key_id = self._get_transport_key_id_if_needed(
            kwargs.get('transport_key_needed'), secret)

        if transport_key_id:
            secret_fields['transport_key_id'] = transport_key_id

        return hrefs.convert_to_hrefs(secret_fields)

    def _get_transport_key_id_if_needed(self, transport_key_needed, secret):
        if transport_key_needed and transport_key_needed.lower() == 'true':
            return plugin.get_transport_key_id_for_retrieval(secret)
        return None

    def _on_get_secret_payload(self, secret, external_project_id, **kwargs):
        """GET actual payload containing the secret."""
        project = res.get_or_create_project(external_project_id,
                                            self.repos.project_repo)

        pecan.override_template('', pecan.request.accept.header_value)

        twsk = kwargs.get('trans_wrapped_session_key', None)
        transport_key = None

        if twsk:
            transport_key = self._get_transport_key(
                kwargs.get('transport_key_id', None))

        return plugin.get_secret(pecan.request.accept.header_value,
                                 secret,
                                 project,
                                 self.repos,
                                 twsk,
                                 transport_key)

    def _get_transport_key(self, transport_key_id):
        if transport_key_id is None:
            _request_has_twsk_but_no_transport_key_id()

        transport_key_model = self.repos.transport_key_repo.get(
            entity_id=transport_key_id,
            suppress_exception=True)

        return transport_key_model.transport_key

    @index.when(method='PUT')
    @allow_all_content_types
    @controllers.handle_exceptions(u._('Secret update'))
    @controllers.enforce_rbac('secret:put')
    @controllers.enforce_content_types(['application/octet-stream',
                                       'text/plain'])
    def on_put(self, external_project_id, **kwargs):

        if (not pecan.request.content_type or
                pecan.request.content_type == 'application/json'):
            pecan.abort(
                415,
                u._("Content-Type of '{content_type}' is not supported for "
                    "PUT.").format(content_type=pecan.request.content_type)
            )

        transport_key_id = kwargs.get('transport_key_id')

        payload = pecan.request.body
        if not payload:
            raise exception.NoDataToProcess()
        if validators.secret_too_big(payload):
            raise exception.LimitExceeded()

        if self.secret.encrypted_data:
            _secret_already_has_data()

        project_model = res.get_or_create_project(external_project_id,
                                                  self.repos.project_repo)
        content_type = pecan.request.content_type
        content_encoding = pecan.request.headers.get('Content-Encoding')

        plugin.store_secret(payload, content_type,
                            content_encoding, self.secret.to_dict_fields(),
                            self.secret, project_model, self.repos,
                            transport_key_id=transport_key_id)

    @index.when(method='DELETE')
    @allow_all_content_types
    @controllers.handle_exceptions(u._('Secret deletion'))
    @controllers.enforce_rbac('secret:delete')
    def on_delete(self, external_project_id, **kwargs):
        plugin.delete_secret(self.secret, external_project_id, self.repos)


class SecretsController(object):
    """Handles Secret creation requests."""

    def __init__(self,
                 project_repo=None, secret_repo=None,
                 project_secret_repo=None, datum_repo=None, kek_repo=None,
                 secret_meta_repo=None, transport_key_repo=None):
        LOG.debug('Creating SecretsController')
        self.validator = validators.NewSecretValidator()
        self.repos = repo.Repositories(project_repo=project_repo,
                                       project_secret_repo=project_secret_repo,
                                       secret_repo=secret_repo,
                                       datum_repo=datum_repo,
                                       kek_repo=kek_repo,
                                       secret_meta_repo=secret_meta_repo,
                                       transport_key_repo=transport_key_repo)

    @pecan.expose()
    def _lookup(self, secret_id, *remainder):
        ctx = controllers._get_barbican_context(pecan.request)

        secret = self.repos.secret_repo.get(
            entity_id=secret_id,
            external_project_id=ctx.project,
            suppress_exception=True)
        if not secret:
            _secret_not_found()

        return SecretController(secret,
                                self.repos.project_repo,
                                self.repos.secret_repo,
                                self.repos.datum_repo,
                                self.repos.kek_repo,
                                self.repos.secret_meta_repo,
                                self.repos.transport_key_repo), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Secret(s) retrieval'))
    @controllers.enforce_rbac('secrets:get')
    def on_get(self, external_project_id, **kw):
        def secret_fields(field):
            return putil.mime_types.augment_fields_with_content_types(field)

        LOG.debug('Start secrets on_get '
                  'for project-ID %s:', external_project_id)

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
            external_project_id,
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
            secrets_resp = [
                hrefs.convert_to_hrefs(secret_fields(s))
                for s in secrets
            ]
            secrets_resp_overall = hrefs.add_nav_hrefs(
                'secrets', offset, limit, total,
                {'secrets': secrets_resp}
            )
            secrets_resp_overall.update({'total': total})

        return secrets_resp_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Secret creation'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        LOG.debug('Start on_post for project-ID %s:...', external_project_id)

        data = api.load_body(pecan.request, validator=self.validator)
        project = res.get_or_create_project(external_project_id,
                                            self.repos.project_repo)

        transport_key_needed = data.get('transport_key_needed',
                                        'false').lower() == 'true'

        new_secret, transport_key_model = plugin.store_secret(
            data.get('payload'),
            data.get('payload_content_type',
                     'application/octet-stream'),
            data.get('payload_content_encoding'),
            data, None, project,
            self.repos,
            transport_key_needed=transport_key_needed,
            transport_key_id=data.get('transport_key_id'))

        pecan.response.status = 201
        pecan.response.headers['Location'] = '/secrets/{0}'.format(
            new_secret.id
        )
        url = hrefs.convert_secret_to_href(new_secret.id)
        LOG.debug('URI to secret is %s', url)
        if transport_key_model is not None:
            tkey_url = hrefs.convert_transport_key_to_href(
                transport_key_model.id)
            return {'secret_ref': url, 'transport_key_ref': tkey_url}
        else:
            return {'secret_ref': url}
