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
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican.model import models
from barbican.model import repositories as repo
from barbican.openstack.common import gettextutils as u

LOG = utils.getLogger(__name__)


def _consumer_not_found():
    """Throw exception indicating consumer not found."""
    pecan.abort(404, u._('Not Found. Sorry but your consumer is in '
                         'another castle.'))


class ContainerConsumerController(object):
    """Handles Consumer entity retrieval and deletion requests."""

    def __init__(self, consumer_id, tenant_repo=None, consumer_repo=None):
        self.consumer_id = consumer_id
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.consumer_repo = consumer_repo or repo.ContainerConsumerRepo()
        self.validator = validators.ContainerConsumerValidator()

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer retrieval'))
    @controllers.enforce_rbac('consumer:get')
    def index(self, keystone_id):
        consumer = self.consumer_repo.get(entity_id=self.consumer_id,
                                          keystone_id=keystone_id,
                                          suppress_exception=True)
        if not consumer:
            _consumer_not_found()

        dict_fields = consumer.to_dict_fields()

        return controllers.hrefs.convert_to_hrefs(
            controllers.hrefs.convert_to_hrefs(dict_fields)
        )


class ContainerConsumersController(object):
    """Handles Consumer creation requests."""

    def __init__(self, container_id, tenant_repo=None, consumer_repo=None,
                 container_repo=None):
        self.container_id = container_id
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.consumer_repo = consumer_repo or repo.ContainerConsumerRepo()
        self.container_repo = container_repo or repo.ContainerRepo()
        self.validator = validators.ContainerConsumerValidator()

    @pecan.expose()
    def _lookup(self, consumer_id, *remainder):
        return ContainerConsumerController(consumer_id, self.tenant_repo,
                                           self.consumer_repo), remainder

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('ContainerConsumers(s) retrieval'))
    @controllers.enforce_rbac('consumers:get')
    def index(self, keystone_id, **kw):
        LOG.debug('Start consumers on_get '
                  'for container-ID {0}:'.format(self.container_id))

        try:
            self.container_repo.get(self.container_id, keystone_id)
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
                controllers.hrefs.convert_to_hrefs(c.to_dict_fields())
                for c in consumers
            ]
            resp_ctrs_overall = controllers.hrefs.add_nav_hrefs(
                'consumers',
                offset,
                limit,
                total,
                {'consumers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer creation'))
    @controllers.enforce_rbac('consumers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, keystone_id, **kwargs):

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...{0}'.format(data))

        try:
            self.container_repo.get(self.container_id, keystone_id)
        except exception.NotFound:
            controllers.containers.container_not_found()

        new_consumer = models.ContainerConsumerMetadatum(self.container_id,
                                                         data)
        new_consumer.tenant_id = tenant.id
        self.consumer_repo.create_from(new_consumer)

        pecan.response.headers['Location'] = '/{0}/containers/{1}/consumers' \
            .format(keystone_id, new_consumer.container_id)

        return self._return_container_data(self.container_id, keystone_id)

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerConsumer deletion'))
    @controllers.enforce_rbac('consumers:delete')
    @controllers.enforce_content_types(['application/json'])
    def on_delete(self, keystone_id, **kwargs):
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug(data)
        consumer = self.consumer_repo.get_by_values(
            self.container_id,
            data["name"],
            data["URL"],
            suppress_exception=True
        )
        if not consumer:
            _consumer_not_found()
        LOG.debug("Found consumer: {0}".format(consumer))

        try:
            self.consumer_repo.delete_entity_by_id(consumer.id, keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting consumer')
            _consumer_not_found()
        return self._return_container_data(self.container_id, keystone_id)

    def _return_container_data(self, container_id, keystone_id):
        try:
            container = self.container_repo.get(container_id, keystone_id)
            dict_fields = container.to_dict_fields()
        except Exception:
            controllers.containers.container_not_found()

        for secret_ref in dict_fields['secret_refs']:
            controllers.hrefs.convert_to_hrefs(secret_ref)

        return controllers.hrefs.convert_to_hrefs(
            controllers.hrefs.convert_to_hrefs(dict_fields)
        )
