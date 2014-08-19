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
from barbican.api.controllers import consumers
from barbican.common import exception
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican.model import models
from barbican.model import repositories as repo
from barbican.openstack.common import gettextutils as u

LOG = utils.getLogger(__name__)


def container_not_found():
    """Throw exception indicating container not found."""
    pecan.abort(404, u._('Not Found. Sorry but your container is in '
                         'another castle.'))


class ContainerController(object):
    """Handles Container entity retrieval and deletion requests."""

    def __init__(self, container_id, tenant_repo=None, container_repo=None,
                 consumer_repo=None):
        #TODO(rm_work): refactor this to use repo-factory method
        self.container_id = container_id
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.container_repo = container_repo or repo.ContainerRepo()
        self.consumer_repo = consumer_repo or repo.ContainerConsumerRepo()
        self.validator = validators.ContainerValidator()
        self.consumers = consumers.ContainerConsumersController(
            container_id, self.tenant_repo, self.consumer_repo,
            self.container_repo)

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Container retrieval'))
    @controllers.enforce_rbac('container:get')
    def index(self, keystone_id):
        container = self.container_repo.get(entity_id=self.container_id,
                                            keystone_id=keystone_id,
                                            suppress_exception=True)
        if not container:
            container_not_found()

        dict_fields = container.to_dict_fields()

        for secret_ref in dict_fields['secret_refs']:
            controllers.hrefs.convert_to_hrefs(secret_ref)

        return controllers.hrefs.convert_to_hrefs(
            controllers.hrefs.convert_to_hrefs(dict_fields)
        )

    @index.when(method='DELETE', template='')
    @controllers.handle_exceptions(u._('Container deletion'))
    @controllers.enforce_rbac('container:delete')
    def on_delete(self, keystone_id, **kwargs):
        try:
            self.container_repo.delete_entity_by_id(
                entity_id=self.container_id,
                keystone_id=keystone_id
            )
        except exception.NotFound:
            LOG.exception('Problem deleting container')
            container_not_found()


class ContainersController(object):
    """Handles Container creation requests."""

    def __init__(self, tenant_repo=None, container_repo=None,
                 secret_repo=None, consumer_repo=None):
        #TODO(rm_work): refactor this to use repo-factory method
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.container_repo = container_repo or repo.ContainerRepo()
        self.secret_repo = secret_repo or repo.SecretRepo()
        self.consumer_repo = consumer_repo or repo.ContainerConsumerRepo()
        self.validator = validators.ContainerValidator()

    @pecan.expose()
    def _lookup(self, container_id, *remainder):
        return (ContainerController(container_id, self.tenant_repo,
                                    self.container_repo, self.consumer_repo),
                remainder)

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Containers(s) retrieval'))
    @controllers.enforce_rbac('containers:get')
    def index(self, keystone_id, **kw):
        LOG.debug('Start containers on_get '
                  'for tenant-ID %s:', keystone_id)

        result = self.container_repo.get_by_create_date(
            keystone_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
            suppress_exception=True
        )

        containers, offset, limit, total = result

        if not containers:
            resp_ctrs_overall = {'containers': [], 'total': total}
        else:
            resp_ctrs = [
                controllers.hrefs.convert_to_hrefs(c.to_dict_fields())
                for c in containers
            ]
            resp_ctrs_overall = controllers.hrefs.add_nav_hrefs(
                'containers',
                offset,
                limit,
                total,
                {'containers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Container creation'))
    @controllers.enforce_rbac('containers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, keystone_id, **kwargs):

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...%s', data)

        new_container = models.Container(data)
        new_container.tenant_id = tenant.id

        #TODO(hgedikli): performance optimizations
        for secret_ref in new_container.container_secrets:
            secret = self.secret_repo.get(entity_id=secret_ref.secret_id,
                                          keystone_id=keystone_id,
                                          suppress_exception=True)
            if not secret:
                # This only partially localizes the error message and
                # doesn't localize secret_ref.name.
                pecan.abort(404, u._("Secret provided for '{0}' doesn't"
                                     " exist.").format(secret_ref.name))

        self.container_repo.create_from(new_container)

        pecan.response.status = 201
        pecan.response.headers['Location'] = '/{0}/containers/{1}'.format(
            keystone_id, new_container.id
        )
        url = controllers.hrefs.convert_container_to_href(new_container.id)
        return {'container_ref': url}
