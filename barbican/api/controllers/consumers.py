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

from barbican import api
from barbican.api import controllers
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.plugin import util as putil

LOG = utils.getLogger(__name__)


def _consumer_not_found():
    """Throw exception indicating consumer not found."""
    pecan.abort(404, u._('Consumer not found.'))


def _consumer_ownership_mismatch():
    """Throw exception indicating the user does not own this consumer."""
    pecan.abort(403, u._('Not Allowed. Sorry, only the creator of a consumer '
                         'can delete it.'))


def _invalid_consumer_id():
    """Throw exception indicating consumer id is invalid."""
    pecan.abort(404, u._('Not Found. Provided consumer id is invalid.'))


class ContainerConsumerController(controllers.ACLMixin):
    """Handles Container Consumer entity retrieval and deletion requests"""

    def __init__(self, container, consumer_id):
        super().__init__()
        self.container = container
        self.consumer_id = consumer_id
        self.consumer_repo = repo.get_container_consumer_repository()
        self.validator = validators.ContainerConsumerValidator()

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer retrieval'))
    @controllers.enforce_rbac('consumer:get')
    def on_get(self, external_project_id):
        consumer = self.consumer_repo.get(
            entity_id=self.consumer_id,
            suppress_exception=True)
        if not consumer:
            _consumer_not_found()

        dict_fields = consumer.to_dict_fields()

        LOG.info('Retrieved a consumer for project: %s',
                 external_project_id)

        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )


class ContainerConsumersController(controllers.ACLMixin):
    """Handles Container Consumer creation requests"""

    def __init__(self, container):
        super().__init__()
        self.container = container
        self.container_id = self.container.id
        self.consumer_repo = repo.get_container_consumer_repository()
        self.container_repo = repo.get_container_repository()
        self.project_repo = repo.get_project_repository()
        self.validator = validators.ContainerConsumerValidator()
        self.quota_enforcer = quota.QuotaEnforcer('consumers',
                                                  self.consumer_repo)

    @pecan.expose()
    def _lookup(self, consumer_id, *remainder):
        if not utils.validate_id_is_uuid(consumer_id):
            _invalid_consumer_id()()
        return ContainerConsumerController(self.container, consumer_id), \
            remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumers(s) retrieval'))
    @controllers.enforce_rbac('container_consumers:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start consumers on_get '
                  'for container-ID %s:', self.container_id)
        result = self.consumer_repo.get_by_container_id(
            self.container_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit'),
            suppress_exception=True
        )

        consumers, offset, limit, total = result

        if not consumers:
            resp_ctrs_overall = {'consumers': [], 'total': total}
        else:
            resp_ctrs = [
                hrefs.convert_to_hrefs(c.to_dict_fields())
                for c in consumers
            ]
            consumer_path = "containers/{container_id}/consumers".format(
                container_id=self.container_id)

            resp_ctrs_overall = hrefs.add_nav_hrefs(
                consumer_path,
                offset,
                limit,
                total,
                {'consumers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        LOG.info('Retrieved a container consumer list for project: %s',
                 external_project_id)
        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer creation'))
    @controllers.enforce_rbac('container_consumers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):

        project = res.get_or_create_project(external_project_id)
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...%s', data)

        self.quota_enforcer.enforce(project)

        new_consumer = models.ContainerConsumerMetadatum(self.container_id,
                                                         project.id,
                                                         data)
        self.consumer_repo.create_or_update_from(new_consumer, self.container)

        url = hrefs.convert_consumer_to_href(new_consumer.container_id)
        pecan.response.headers['Location'] = url

        LOG.info('Created a container consumer for project: %s',
                 external_project_id)

        return self._return_container_data()

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer deletion'))
    @controllers.enforce_rbac('container_consumers:delete')
    @controllers.enforce_content_types(['application/json'])
    def on_delete(self, external_project_id, **kwargs):
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_delete...%s', data)
        project = res.get_or_create_project(external_project_id)

        consumer = self.consumer_repo.get_by_values(
            self.container_id,
            data["name"],
            data["URL"],
            suppress_exception=True
        )
        if not consumer:
            _consumer_not_found()
        LOG.debug("Found container consumer: %s", consumer)

        owner_of_consumer = consumer.project_id == project.id
        owner_of_container = self.container.project.external_id \
            == external_project_id
        if not owner_of_consumer and not owner_of_container:
            _consumer_ownership_mismatch()

        try:
            self.consumer_repo.delete_entity_by_id(consumer.id,
                                                   external_project_id)
        except exception.NotFound:
            LOG.exception('Problem deleting container consumer')
            _consumer_not_found()

        ret_data = self._return_container_data()
        LOG.info('Deleted a container consumer for project: %s',
                 external_project_id)
        return ret_data

    def _return_container_data(self):
        dict_fields = self.container.to_dict_fields()

        for secret_ref in dict_fields['secret_refs']:
            hrefs.convert_to_hrefs(secret_ref)

        # TODO(john-wood-w) Why two calls to convert_to_hrefs()?
        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )


class SecretConsumerController(controllers.ACLMixin):
    """Handles Secret Consumer entity retrieval and deletion requests"""

    def __init__(self, secret, consumer_id):
        super().__init__()
        self.secret = secret
        self.consumer_id = consumer_id
        self.consumer_repo = repo.get_secret_consumer_repository()
        self.validator = validators.SecretConsumerValidator()

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('SecretConsumer retrieval'))
    @controllers.enforce_rbac('consumer:get')
    def on_get(self, external_project_id):
        consumer = self.consumer_repo.get(
            entity_id=self.consumer_id,
            suppress_exception=True)
        if not consumer:
            _consumer_not_found()

        dict_fields = consumer.to_dict_fields()

        LOG.info('Retrieved a secret consumer for project: %s',
                 external_project_id)

        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )


class SecretConsumersController(controllers.ACLMixin):
    """Handles Secret Consumer creation requests"""

    def __init__(self, secret):
        super().__init__()
        self.secret = secret
        self.secret_id = secret.id
        self.consumer_repo = repo.get_secret_consumer_repository()
        self.secret_repo = repo.get_secret_repository()
        self.project_repo = repo.get_project_repository()
        self.validator = validators.SecretConsumerValidator()
        self.quota_enforcer = quota.QuotaEnforcer('consumers',
                                                  self.consumer_repo)

    @pecan.expose()
    def _lookup(self, consumer_id, *remainder):
        if not utils.validate_id_is_uuid(consumer_id):
            _invalid_consumer_id()()
        return SecretConsumerController(self.secret, consumer_id), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('SecretConsumers(s) retrieval'))
    @controllers.enforce_rbac('secret_consumers:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start consumers on_get '
                  'for secret-ID %s:', self.secret_id)
        result = self.consumer_repo.get_by_secret_id(
            self.secret_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit'),
            suppress_exception=True
        )

        consumers, offset, limit, total = result

        if not consumers:
            resp_ctrs_overall = {'consumers': [], 'total': total}
        else:
            resp_ctrs = [
                hrefs.convert_to_hrefs(c.to_dict_fields())
                for c in consumers
            ]
            consumer_path = "secrets/{secret_id}/consumers".format(
                secret_id=self.secret_id)

            resp_ctrs_overall = hrefs.add_nav_hrefs(
                consumer_path,
                offset,
                limit,
                total,
                {'consumers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        LOG.info('Retrieved a consumer list for project: %s',
                 external_project_id)
        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('SecretConsumer creation'))
    @controllers.enforce_rbac('secret_consumers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):

        project = res.get_or_create_project(external_project_id)
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...%s', data)

        self.quota_enforcer.enforce(project)

        new_consumer = models.SecretConsumerMetadatum(
            self.secret_id,
            project.id,
            data["service"],
            data["resource_type"],
            data["resource_id"],
        )
        self.consumer_repo.create_or_update_from(new_consumer, self.secret)

        url = hrefs.convert_consumer_to_href(new_consumer.secret_id)
        pecan.response.headers['Location'] = url

        LOG.info('Created a consumer for project: %s',
                 external_project_id)

        return self._return_secret_data(self.secret_id)

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('SecretConsumer deletion'))
    @controllers.enforce_rbac('secret_consumers:delete')
    @controllers.enforce_content_types(['application/json'])
    def on_delete(self, external_project_id, **kwargs):
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_delete...%s', data)
        project = self.project_repo.find_by_external_project_id(
            external_project_id, suppress_exception=True)
        if not project:
            _consumer_not_found()

        consumer = self.consumer_repo.get_by_values(
            self.secret_id,
            data["service"],
            data["resource_type"],
            data["resource_id"],
            suppress_exception=True
        )
        if not consumer:
            _consumer_not_found()
        LOG.debug("Found consumer: %s", consumer)

        owner_of_consumer = consumer.project_id == project.id
        owner_of_secret = self.secret.project.external_id \
            == external_project_id
        if not owner_of_consumer and not owner_of_secret:
            _consumer_ownership_mismatch()

        try:
            self.consumer_repo.delete_entity_by_id(consumer.id,
                                                   external_project_id)
        except exception.NotFound:
            LOG.exception('Problem deleting consumer')
            _consumer_not_found()

        ret_data = self._return_secret_data(self.secret_id)
        LOG.info('Deleted a secret consumer for project: %s',
                 external_project_id)
        return ret_data

    def _get_secret(self, secret_id):
        secret = self.secret_repo.get_secret_by_id(
            secret_id, suppress_exception=True)
        if not secret:
            controllers.secrets.secret_not_found()
        return secret

    def _return_secret_data(self, secret_id):
        secret = self._get_secret(secret_id)

        secret_fields = putil.mime_types.augment_fields_with_content_types(
            secret)

        return hrefs.convert_to_hrefs(secret_fields)
