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
from six.moves.urllib import parse

from barbican import api
from barbican.api import controllers
from barbican.api.controllers import acls
from barbican.api.controllers import secretmeta
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.plugin import resources as plugin
from barbican.plugin import util as putil


LOG = utils.getLogger(__name__)


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


class SecretController(controllers.ACLMixin):
    """Handles Secret retrieval and deletion requests."""

    def __init__(self, secret):
        LOG.debug('=== Creating SecretController ===')
        self.secret = secret
        self.transport_key_repo = repo.get_transport_key_repository()

    def get_acl_tuple(self, req, **kwargs):
        d = self.get_acl_dict_for_user(req, self.secret.secret_acls)
        d['project_id'] = self.secret.project.external_id
        d['creator_id'] = self.secret.creator_id
        return 'secret', d

    @pecan.expose()
    def _lookup(self, sub_resource, *remainder):
        if sub_resource == 'acl':
            return acls.SecretACLsController(self.secret), remainder
        elif sub_resource == 'metadata':
            if len(remainder) == 0 or remainder == ('',):
                return secretmeta.SecretMetadataController(self.secret), \
                    remainder
            else:
                request_method = pecan.request.method
                allowed_methods = ['GET', 'PUT', 'DELETE']

                if request_method in allowed_methods:
                    return secretmeta.SecretMetadatumController(self.secret), \
                        remainder
                else:
                    # methods cannot be handled at controller level
                    pecan.abort(405)
        else:
            # only 'acl' and 'metadata' as sub-resource is supported
            pecan.abort(405)

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Secret retrieval'))
    @controllers.enforce_rbac('secret:get')
    def on_get(self, external_project_id, **kwargs):
        if controllers.is_json_request_accept(pecan.request):
            resp = self._on_get_secret_metadata(self.secret, **kwargs)

            LOG.info(u._LI('Retrieved secret metadata for project: %s'),
                     external_project_id)
            return resp
        else:
            LOG.warning(u._LW('Decrypted secret %s requested using deprecated '
                        'API call.'), self.secret.id)
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

        # With ACL support, the user token project does not have to be same as
        # project associated with secret. The lookup project_id needs to be
        # derived from the secret's data considering authorization is already
        # done.
        external_project_id = secret.project.external_id
        project = res.get_or_create_project(external_project_id)

        # default to application/octet-stream if there is no Accept header
        accept_header = getattr(pecan.request.accept, 'header_value',
                                'application/octet-stream')
        pecan.override_template('', accept_header)

        twsk = kwargs.get('trans_wrapped_session_key', None)
        transport_key = None

        if twsk:
            transport_key = self._get_transport_key(
                kwargs.get('transport_key_id', None))

        return plugin.get_secret(accept_header,
                                 secret,
                                 project,
                                 twsk,
                                 transport_key)

    def _get_transport_key(self, transport_key_id):
        if transport_key_id is None:
            _request_has_twsk_but_no_transport_key_id()

        transport_key_model = self.transport_key_repo.get(
            entity_id=transport_key_id,
            suppress_exception=True)

        return transport_key_model.transport_key

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Secret payload retrieval'))
    @controllers.enforce_rbac('secret:decrypt')
    def payload(self, external_project_id, **kwargs):
        if pecan.request.method != 'GET':
            pecan.abort(405)
        resp = self._on_get_secret_payload(
            self.secret,
            external_project_id,
            **kwargs
        )

        LOG.info(u._LI('Retrieved secret payload for project: %s'),
                 external_project_id)
        return resp

    @index.when(method='PUT')
    @utils.allow_all_content_types
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

        if self.secret.encrypted_data or self.secret.secret_store_metadata:
            _secret_already_has_data()

        project_model = res.get_or_create_project(external_project_id)
        content_type = pecan.request.content_type
        content_encoding = pecan.request.headers.get('Content-Encoding')

        plugin.store_secret(
            unencrypted_raw=payload,
            content_type_raw=content_type,
            content_encoding=content_encoding,
            secret_model=self.secret,
            project_model=project_model,
            transport_key_id=transport_key_id)
        LOG.info(u._LI('Updated secret for project: %s'), external_project_id)

    @index.when(method='DELETE')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Secret deletion'))
    @controllers.enforce_rbac('secret:delete')
    def on_delete(self, external_project_id, **kwargs):
        plugin.delete_secret(self.secret, external_project_id)
        LOG.info(u._LI('Deleted secret for project: %s'), external_project_id)


class SecretsController(controllers.ACLMixin):
    """Handles Secret creation requests."""

    def __init__(self):
        LOG.debug('Creating SecretsController')
        self.validator = validators.NewSecretValidator()
        self.secret_repo = repo.get_secret_repository()
        self.quota_enforcer = quota.QuotaEnforcer('secrets', self.secret_repo)

    @pecan.expose()
    def _lookup(self, secret_id, *remainder):
        # NOTE(jaosorior): It's worth noting that even though this section
        # actually does a lookup in the database regardless of the RBAC policy
        # check, the execution only gets here if authentication of the user was
        # previously successful.

        secret = self.secret_repo.get_secret_by_id(
            entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()

        return SecretController(secret), remainder

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
            name = parse.unquote_plus(name)

        bits = kw.get('bits', 0)
        try:
            bits = int(bits)
        except ValueError:
            # as per Github issue 171, if bits is invalid then
            # the default should be used.
            bits = 0

        ctxt = controllers._get_barbican_context(pecan.request)
        user_id = None
        if ctxt:
            user_id = ctxt.user

        result = self.secret_repo.get_by_create_date(
            external_project_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
            name=name,
            alg=kw.get('alg'),
            mode=kw.get('mode'),
            bits=bits,
            suppress_exception=True,
            acl_only=kw.get('acl_only', None),
            user_id=user_id
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

        LOG.info(u._LI('Retrieved secret list for project: %s'),
                 external_project_id)
        return secrets_resp_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Secret creation'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        LOG.debug('Start on_post for project-ID %s:...', external_project_id)

        data = api.load_body(pecan.request, validator=self.validator)
        project = res.get_or_create_project(external_project_id)

        self.quota_enforcer.enforce(project)

        transport_key_needed = data.get('transport_key_needed',
                                        'false').lower() == 'true'
        ctxt = controllers._get_barbican_context(pecan.request)
        if ctxt:  # in authenticated pipleline case, always use auth token user
            data['creator_id'] = ctxt.user

        secret_model = models.Secret(data)

        new_secret, transport_key_model = plugin.store_secret(
            unencrypted_raw=data.get('payload'),
            content_type_raw=data.get('payload_content_type',
                                      'application/octet-stream'),
            content_encoding=data.get('payload_content_encoding'),
            secret_model=secret_model,
            project_model=project,
            transport_key_needed=transport_key_needed,
            transport_key_id=data.get('transport_key_id'))

        url = hrefs.convert_secret_to_href(new_secret.id)
        LOG.debug('URI to secret is %s', url)

        pecan.response.status = 201
        pecan.response.headers['Location'] = url

        LOG.info(u._LI('Created a secret for project: %s'),
                 external_project_id)
        if transport_key_model is not None:
            tkey_url = hrefs.convert_transport_key_to_href(
                transport_key_model.id)
            return {'secret_ref': url, 'transport_key_ref': tkey_url}
        else:
            return {'secret_ref': url}
