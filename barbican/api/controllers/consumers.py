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

LOG = utils.getLogger(__name__)


def _consumer_not_found():
    """Throw exception indicating consumer not found."""
    pecan.abort(404, u._('Not Found. Sorry but your consumer is in '
                         'another castle.'))


class ContainerConsumerController(controllers.ACLMixin):
    """Handles Consumer entity retrieval and deletion requests."""

    def __init__(self, consumer_id):
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
            external_project_id=external_project_id,
            suppress_exception=True)
        if not consumer:
            _consumer_not_found()

        dict_fields = consumer.to_dict_fields()

        LOG.info(u._LI('Retrieved a consumer for project: %s'),
                 external_project_id)

        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )


class ContainerConsumersController(controllers.ACLMixin):
    """Handles Consumer creation requests."""

    def __init__(self, container_id):
        self.container_id = container_id
        self.consumer_repo = repo.get_container_consumer_repository()
        self.container_repo = repo.get_container_repository()
        self.validator = validators.ContainerConsumerValidator()
        self.quota_enforcer = quota.QuotaEnforcer('consumers',
                                                  self.consumer_repo)

    @pecan.expose()
    def _lookup(self, consumer_id, *remainder):
        return ContainerConsumerController(consumer_id), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumers(s) retrieval'))
    @controllers.enforce_rbac('consumers:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start consumers on_get '
                  'for container-ID %s:', self.container_id)

        try:
            self.container_repo.get(self.container_id, external_project_id)
        except exception.NotFound:
            controllers.containers.container_not_found()

        result = self.consumer_repo.get_by_container_id(
            self.container_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
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
            resp_ctrs_overall = hrefs.add_nav_hrefs(
                'consumers',
                offset,
                limit,
                total,
                {'consumers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        LOG.info(u._LI('Retrieved a consumer list for project: %s'),
                 external_project_id)
        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer creation'))
    @controllers.enforce_rbac('consumers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):

        project = res.get_or_create_project(external_project_id)
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...%s', data)

        try:
            container = self.container_repo.get(self.container_id,
                                                external_project_id)
        except exception.NotFound:
            controllers.containers.container_not_found()

        self.quota_enforcer.enforce(project)

        new_consumer = models.ContainerConsumerMetadatum(self.container_id,
                                                         project.id,
                                                         data)
        new_consumer.project_id = project.id
        self.consumer_repo.create_or_update_from(new_consumer, container)

        url = hrefs.convert_consumer_to_href(new_consumer.container_id)
        pecan.response.headers['Location'] = url

        LOG.info(u._LI('Created a consumer for project: %s'),
                 external_project_id)

        return self._return_container_data(self.container_id,
                                           external_project_id)

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer deletion'))
    @controllers.enforce_rbac('consumers:delete')
    @controllers.enforce_content_types(['application/json'])
    def on_delete(self, external_project_id, **kwargs):
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_delete...%s', data)
        consumer = self.consumer_repo.get_by_values(
            self.container_id,
            data["name"],
            data["URL"],
            suppress_exception=True
        )
        if not consumer:
            _consumer_not_found()
        LOG.debug("Found consumer: %s", consumer)

        try:
            self.consumer_repo.delete_entity_by_id(consumer.id,
                                                   external_project_id)
        except exception.NotFound:
            LOG.exception(u._LE('Problem deleting consumer'))
            _consumer_not_found()

        ret_data = self._return_container_data(
            self.container_id,
            external_project_id
        )
        LOG.info(u._LI('Deleted a consumer for project: %s'),
                 external_project_id)
        return ret_data

    def _return_container_data(self, container_id, external_project_id):
        try:
            container = self.container_repo.get(container_id,
                                                external_project_id)
            dict_fields = container.to_dict_fields()
        except Exception:
            controllers.containers.container_not_found()

        for secret_ref in dict_fields['secret_refs']:
            hrefs.convert_to_hrefs(secret_ref)

        # TODO(john-wood-w) Why two calls to convert_to_hrefs()?
        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )
