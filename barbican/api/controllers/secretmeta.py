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
import collections
import pecan

from barbican import api
from barbican.api import controllers
from barbican.common import hrefs
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import repositories as repo

LOG = utils.getLogger(__name__)


def _secret_metadata_not_found():
    """Throw exception indicating secret metadata not found."""
    pecan.abort(404, u._('Secret metadata not found.'))


class SecretMetadataController(controllers.ACLMixin):
    """Handles SecretMetadata requests by a given secret id."""

    def __init__(self, secret):
        LOG.debug('=== Creating SecretMetadataController ===')
        super().__init__()
        self.secret = secret
        self.secret_project_id = self.secret.project.external_id
        self.secret_repo = repo.get_secret_repository()
        self.user_meta_repo = repo.get_secret_user_meta_repository()
        self.metadata_validator = validators.NewSecretMetadataValidator()
        self.metadatum_validator = validators.NewSecretMetadatumValidator()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Secret metadata retrieval'))
    @controllers.enforce_rbac('secret_meta:get')
    def on_get(self, external_project_id, **kwargs):
        """Handles retrieval of existing secret metadata requests."""

        LOG.debug('Start secret metadata on_get '
                  'for secret-ID %s:', self.secret.id)

        resp = self.user_meta_repo.get_metadata_for_secret(self.secret.id)
        pecan.response.status = 200

        return {"metadata": resp}

    @index.when(method='PUT', template='json')
    @controllers.handle_exceptions(u._('Secret metadata creation'))
    @controllers.enforce_rbac('secret_meta:put')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, external_project_id, **kwargs):
        """Handles creation/update of secret metadata."""
        data = api.load_body(pecan.request, validator=self.metadata_validator)
        LOG.debug('Start secret metadata on_put...%s', data)

        self.user_meta_repo.create_replace_user_metadata(self.secret.id,
                                                         data)

        url = hrefs.convert_user_meta_to_href(self.secret.id)
        LOG.debug('URI to secret metadata is %s', url)

        pecan.response.status = 201
        return {'metadata_ref': url}

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Secret metadatum creation'))
    @controllers.enforce_rbac('secret_meta:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        """Handles creation of secret metadatum."""

        data = api.load_body(pecan.request, validator=self.metadatum_validator)

        key = data.get('key')
        value = data.get('value')

        metadata = self.user_meta_repo.get_metadata_for_secret(self.secret.id)
        if key in metadata:
            pecan.abort(409, u._('Conflict. Key in request is already in the '
                                 'secret metadata'))

        LOG.debug('Start secret metadatum on_post...%s', metadata)
        self.user_meta_repo.create_replace_user_metadatum(self.secret.id,
                                                          key, value)

        url = hrefs.convert_user_meta_to_href(self.secret.id)
        LOG.debug('URI to secret metadata is %s', url)

        pecan.response.status = 201
        pecan.response.headers['Location'] = url + '/' + key
        return {'key': key, 'value': value}


class SecretMetadatumController(controllers.ACLMixin):

    def __init__(self, secret):
        LOG.debug('=== Creating SecretMetadatumController ===')
        super().__init__()
        self.user_meta_repo = repo.get_secret_user_meta_repository()
        self.secret = secret
        self.metadatum_validator = validators.NewSecretMetadatumValidator()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Secret metadatum retrieval'))
    @controllers.enforce_rbac('secret_meta:get')
    def on_get(self, external_project_id, remainder, **kwargs):
        """Handles retrieval of existing secret metadatum."""

        LOG.debug('Start secret metadatum on_get '
                  'for secret-ID %s:', self.secret.id)

        metadata = self.user_meta_repo.get_metadata_for_secret(self.secret.id)
        if remainder in metadata:
            pecan.response.status = 200
            pair = {'key': remainder, 'value': metadata[remainder]}
            return collections.OrderedDict(sorted(pair.items()))
        else:
            _secret_metadata_not_found()

    @index.when(method='PUT', template='json')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Secret metadatum update'))
    @controllers.enforce_rbac('secret_meta:put')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, external_project_id, remainder, **kwargs):
        """Handles update of existing secret metadatum."""
        metadata = self.user_meta_repo.get_metadata_for_secret(self.secret.id)
        data = api.load_body(pecan.request, validator=self.metadatum_validator)

        key = data.get('key')
        value = data.get('value')

        if remainder not in metadata:
            _secret_metadata_not_found()
        elif remainder != key:
            msg = 'Key in request data does not match key in the '
            'request url.'
            pecan.abort(409, msg)
        else:
            LOG.debug('Start secret metadatum on_put...%s', metadata)

            self.user_meta_repo.create_replace_user_metadatum(self.secret.id,
                                                              key, value)

            pecan.response.status = 200
            pair = {'key': key, 'value': value}
            return collections.OrderedDict(sorted(pair.items()))

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('Secret metadatum removal'))
    @controllers.enforce_rbac('secret_meta:delete')
    def on_delete(self, external_project_id, remainder, **kwargs):
        """Handles removal of existing secret metadatum."""

        self.user_meta_repo.delete_metadatum(self.secret.id,
                                             remainder)
        msg = 'Deleted secret metadatum: %s for secret %s' % (remainder,
                                                              self.secret.id)
        pecan.response.status = 204
        LOG.info(msg)
