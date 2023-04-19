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
from barbican.api.controllers import acls
from barbican.api.controllers import consumers
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

CONTAINER_GET = 'container:get'


def container_not_found():
    """Throw exception indicating container not found."""
    pecan.abort(404, u._('Secrets container not found.'))


def invalid_container_id():
    """Throw exception indicating container id is invalid."""
    pecan.abort(404, u._('Not Found. Provided container id is invalid.'))


class ContainerController(controllers.ACLMixin):
    """Handles Container entity retrieval and deletion requests."""

    def __init__(self, container):
        super().__init__()
        self.container = container
        self.container_id = container.id
        self.consumer_repo = repo.get_container_consumer_repository()
        self.container_repo = repo.get_container_repository()
        self.validator = validators.ContainerValidator()
        self.consumers = consumers.ContainerConsumersController(
            self.container)
        self.acl = acls.ContainerACLsController(self.container)

    @pecan.expose(generic=True, template='json')
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Container retrieval'))
    @controllers.enforce_rbac(CONTAINER_GET)
    def on_get(self, external_project_id):
        dict_fields = self.container.to_dict_fields()

        for secret_ref in dict_fields['secret_refs']:
            hrefs.convert_to_hrefs(secret_ref)

        LOG.info('Retrieved container for project: %s',
                 external_project_id)
        return hrefs.convert_to_hrefs(
            hrefs.convert_to_hrefs(dict_fields)
        )

    @index.when(method='DELETE')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Container deletion'))
    @controllers.enforce_rbac('container:delete')
    def on_delete(self, external_project_id, **kwargs):
        container_consumers = self.consumer_repo.get_by_container_id(
            self.container_id,
            suppress_exception=True
        )
        try:
            self.container_repo.delete_entity_by_id(
                entity_id=self.container_id,
                external_project_id=external_project_id
            )
        except exception.NotFound:
            LOG.exception('Problem deleting container')
            container_not_found()

        LOG.info('Deleted container for project: %s',
                 external_project_id)

        for consumer in container_consumers[0]:
            try:
                self.consumer_repo.delete_entity_by_id(
                    consumer.id, external_project_id)
            except exception.NotFound:  # nosec
                pass


class ContainersController(controllers.ACLMixin):
    """Handles Container creation requests."""

    def __init__(self):
        super().__init__()
        self.consumer_repo = repo.get_container_consumer_repository()
        self.container_repo = repo.get_container_repository()
        self.secret_repo = repo.get_secret_repository()
        self.validator = validators.ContainerValidator()
        self.quota_enforcer = quota.QuotaEnforcer('containers',
                                                  self.container_repo)

    @pecan.expose()
    def _lookup(self, container_id, *remainder):
        if not utils.validate_id_is_uuid(container_id):
            invalid_container_id()
        container = self.container_repo.get_container_by_id(
            entity_id=container_id, suppress_exception=True)
        if not container:
            container_not_found()

        if len(remainder) > 0 and remainder[0] == 'secrets':
            return ContainersSecretsController(container), ()

        return ContainerController(container), remainder

    @pecan.expose(generic=True, template='json')
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Containers(s) retrieval'))
    @controllers.enforce_rbac('containers:get')
    def on_get(self, project_id, **kw):
        LOG.debug('Start containers on_get for project-ID %s:', project_id)

        result = self.container_repo.get_by_create_date(
            project_id,
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
            name_arg=kw.get('name', None),
            type_arg=kw.get('type', None),
            suppress_exception=True
        )

        containers, offset, limit, total = result

        if not containers:
            resp_ctrs_overall = {'containers': [], 'total': total}
        else:
            resp_ctrs = [
                hrefs.convert_to_hrefs(c.to_dict_fields())
                for c in containers
            ]

            for ctr in resp_ctrs:
                for secret_ref in ctr.get('secret_refs', []):
                    hrefs.convert_to_hrefs(secret_ref)

            resp_ctrs_overall = hrefs.add_nav_hrefs(
                'containers',
                offset,
                limit,
                total,
                {'containers': resp_ctrs}
            )
            resp_ctrs_overall.update({'total': total})

        LOG.info('Retrieved container list for project: %s', project_id)
        return resp_ctrs_overall

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Container creation'))
    @controllers.enforce_rbac('containers:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):

        project = res.get_or_create_project(external_project_id)

        data = api.load_body(pecan.request, validator=self.validator)
        ctxt = controllers._get_barbican_context(pecan.request)
        if ctxt:  # in authenticated pipleline case, always use auth token user
            data['creator_id'] = ctxt.user_id

        self.quota_enforcer.enforce(project)

        LOG.debug('Start on_post...%s', data)

        new_container = models.Container(data)
        new_container.project_id = project.id

        # TODO(hgedikli): performance optimizations
        for secret_ref in new_container.container_secrets:
            secret = self.secret_repo.get(
                entity_id=secret_ref.secret_id,
                external_project_id=external_project_id,
                suppress_exception=True)
            if not secret:
                # This only partially localizes the error message and
                # doesn't localize secret_ref.name.
                pecan.abort(
                    404,
                    u._("Secret provided for '{secret_name}' doesn't "
                        "exist.").format(secret_name=secret_ref.name)
                )

        self.container_repo.create_from(new_container)

        url = hrefs.convert_container_to_href(new_container.id)

        pecan.response.status = 201
        pecan.response.headers['Location'] = url
        LOG.info('Created a container for project: %s',
                 external_project_id)

        return {'container_ref': url}


class ContainersSecretsController(controllers.ACLMixin):
    """Handles ContainerSecret creation and deletion requests."""

    def __init__(self, container):
        LOG.debug('=== Creating ContainerSecretsController ===')
        super().__init__()
        self.container = container
        self.container_secret_repo = repo.get_container_secret_repository()
        self.secret_repo = repo.get_secret_repository()
        self.validator = validators.ContainerSecretValidator()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Container Secret creation'))
    @controllers.enforce_rbac('container_secret:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        """Handles adding an existing secret to an existing container."""

        if self.container.type != 'generic':
            pecan.abort(400, u._("Only 'generic' containers can be modified."))

        data = api.load_body(pecan.request, validator=self.validator)

        name = data.get('name')
        secret_ref = data.get('secret_ref')
        secret_id = hrefs.get_secret_id_from_ref(secret_ref)

        secret = self.secret_repo.get(
            entity_id=secret_id,
            external_project_id=external_project_id,
            suppress_exception=True)
        if not secret:
            pecan.abort(404, u._("Secret provided doesn't exist."))

        found_container_secrets = list(
            filter(lambda cs: cs.secret_id == secret_id and cs.name == name,
                   self.container.container_secrets)
        )

        if found_container_secrets:
            pecan.abort(409, u._('Conflict. A secret with that name and ID is '
                                 'already stored in this container. The same '
                                 'secret can exist in a container as long as '
                                 'the name is unique.'))

        LOG.debug('Start container secret on_post...%s', secret_ref)
        new_container_secret = models.ContainerSecret()
        new_container_secret.container_id = self.container.id
        new_container_secret.name = name
        new_container_secret.secret_id = secret_id
        self.container_secret_repo.save(new_container_secret)

        url = hrefs.convert_container_to_href(self.container.id)
        LOG.debug('URI to container is %s', url)

        pecan.response.status = 201
        pecan.response.headers['Location'] = url
        LOG.info('Created a container secret for project: %s',
                 external_project_id)

        return {'container_ref': url}

    @index.when(method='DELETE')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Container Secret deletion'))
    @controllers.enforce_rbac('container_secret:delete')
    def on_delete(self, external_project_id, **kwargs):
        """Handles removing a secret reference from an existing container."""

        data = api.load_body(pecan.request, validator=self.validator)

        name = data.get('name')
        secret_ref = data.get('secret_ref')
        secret_id = hrefs.get_secret_id_from_ref(secret_ref)

        secret = self.secret_repo.get(
            entity_id=secret_id,
            external_project_id=external_project_id,
            suppress_exception=True)
        if not secret:
            pecan.abort(404, u._("Secret '{secret_name}' with reference "
                                 "'{secret_ref}' doesn't exist.").format(
                                     secret_name=name, secret_ref=secret_ref))

        found_container_secrets = list(
            filter(lambda cs: cs.secret_id == secret_id and cs.name == name,
                   self.container.container_secrets)
        )

        if not found_container_secrets:
            pecan.abort(404, u._('Secret provided is not in the container'))

        for container_secret in found_container_secrets:
            self.container_secret_repo.delete_entity_by_id(
                container_secret.id, external_project_id)

        pecan.response.status = 204
        LOG.info('Deleted container secret for project: %s',
                 external_project_id)
