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

import itertools

import pecan

from barbican import api
from barbican.api import controllers
from barbican.common import hrefs
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo

LOG = utils.getLogger(__name__)


def _acls_not_found(acl_for=None):
    """Throw exception indicating no secret or container acls found."""
    pecan.abort(404, u._('Not Found. Sorry no ACL found for given {0}.').
                format(acl_for))


def _acl_not_found():
    """Throw exception indicating no secret or container acl found."""
    pecan.abort(404, u._('Not Found. Sorry no ACL found for given id.'))


def _acls_already_exist():
    """Throw exception indicating secret or container acls already exist."""
    pecan.abort(400, u._('Existing ACL cannot be updated with POST method.'))


def _acl_operation_update_not_allowed():
    """Throw exception indicating existing secret or container acl operation.

    Operation cannot be changed for an existing ACL. Allowed change is list of
    users and/or creator_only flag change.
    """
    pecan.abort(400, u._("Existing ACL's operation cannot be updated."))


class SecretACLController(controllers.ACLMixin):
    """Handles a SecretACL entity retrieval and update requests."""

    def __init__(self, acl_id, secret_project_id, secret):
        self.acl_id = acl_id
        self.secret_project_id = secret_project_id
        self.secret = secret
        self.acl_repo = repo.get_secret_acl_repository()
        self.validator = validators.ACLValidator()

    def get_acl_tuple(self, req, **kwargs):
        d = {'project_id': self.secret_project_id}
        return 'secret', d

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('SecretACL retrieval'))
    @controllers.enforce_rbac('secret_acl:get')
    def on_get(self, external_project_id):
        secret_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)

        if not secret_acl:
            _acl_not_found()

        dict_fields = secret_acl.to_dict_fields()

        return hrefs.convert_acl_to_hrefs(dict_fields)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('A SecretACL Update'))
    @controllers.enforce_rbac('secret_acl:patch')
    @controllers.enforce_content_types(['application/json'])
    def on_patch(self, external_project_id, **kwargs):
        """Handles existing secret ACL update for given acl id."""

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start SecretACLController on_patch...%s', data)

        secret_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)
        if not secret_acl:
            _acl_not_found()

        # Make sure request acl operation matches with acl stored in db
        operation = secret_acl.operation
        input_acl = data.get(operation)
        if not input_acl:
            _acl_operation_update_not_allowed()

        creator_only = input_acl.get('creator-only')
        user_ids = input_acl.get('users')
        if creator_only is not None:
            secret_acl.creator_only = creator_only

        self.acl_repo.create_or_replace_from(self.secret,
                                             secret_acl=secret_acl,
                                             user_ids=user_ids)
        acl_ref = hrefs.convert_acl_to_hrefs(secret_acl.to_dict_fields())

        return {'acl_ref': acl_ref['acl_ref']}

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('SecretACL deletion'))
    @controllers.enforce_rbac('secret_acl:delete')
    def on_delete(self, external_project_id, **kwargs):
        """Deletes existing ACL by acl_id provided in URI."""

        secret_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)

        if not secret_acl:
            _acl_not_found()

        self.acl_repo.delete_entity_by_id(entity_id=self.acl_id,
                                          external_project_id=None)


class SecretACLsController(controllers.ACLMixin):
    """Handles SecretACL requests by a given secret id."""

    def __init__(self, secret):
        self.secret = secret
        self.secret_project_id = (self.secret.project_assocs[0].
                                  projects.external_id)
        self.acl_repo = repo.get_secret_acl_repository()
        self.validator = validators.ACLValidator()

    def get_acl_tuple(self, req, **kwargs):
        d = {'project_id': self.secret_project_id}
        return 'secret', d

    @pecan.expose()
    def _lookup(self, acl_id, *remainder):
        return SecretACLController(acl_id, self.secret_project_id,
                                   self.secret), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) retrieval'))
    @controllers.enforce_rbac('secret_acls:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start secret ACL on_get '
                  'for secret-ID %s:', self.secret.id)

        return self._return_acl_hrefs(self.secret.id)

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) creation'))
    @controllers.enforce_rbac('secret_acls:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        """Handles secret acls creation request.

        Once a set of ACLs exists for a given secret, it can only be updated
        via PATCH method. In create, multiple operation ACL payload can be
        specified as mentioned in sample below.

        {
          "read":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a"
            ]
          },
          "write":{
            "users":[
              "20b63d71f90848cf827ee48074f213b7",
              "5ecb18f341894e94baca9e8c7b6a824a"
            ],
            "creator-only":false
          }
        }
        """

        count = self.acl_repo.get_count(self.secret.id)
        LOG.debug('Count of existing ACL on_post is [%s] '
                  ' for secret-ID %s:', count, self.secret.id)
        if count > 0:
            _acls_already_exist()

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...%s', data)

        for operation in itertools.ifilter(lambda x: data.get(x),
                                           validators.ACL_OPERATIONS):
            input_cr_only = data[operation].get('creator-only')
            creator_only = True if input_cr_only else False
            new_acl = models.SecretACL(self.secret.id, operation=operation,
                                       creator_only=creator_only)
            self.acl_repo.create_or_replace_from(
                self.secret, secret_acl=new_acl,
                user_ids=data[operation].get('users'))

        pecan.response.status = 201
        return self._return_acl_hrefs(self.secret.id)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) Update'))
    @controllers.enforce_rbac('secret_acls:patch')
    @controllers.enforce_content_types(['application/json'])
    def on_patch(self, external_project_id, **kwargs):
        """Handles update of existing secret acl requests.

        At least one secret ACL needs to exist for update to proceed.
        In update, multiple operation ACL payload can be specified as
        mentioned in sample below. A specific ACL can be updated by its
        own id via SecretACLController patch request.

        {
          "read":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a",
              "20b63d71f90848cf827ee48074f213b7",
              "c7753f8da8dc4fbea75730ab0b6e0ef4"
            ]
          },
          "write":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a"
            ],
            "creator-only":true
          }
        }
        """

        count = self.acl_repo.get_count(self.secret.id)
        LOG.debug('Count of existing ACL on_secret is [%s] '
                  ' for secret-ID %s:', count, self.secret.id)
        if count == 0:
            _acls_not_found("secret")

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_patch...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.secret.secret_acls}
        for operation in itertools.ifilter(lambda x: data.get(x),
                                           validators.ACL_OPERATIONS):
            creator_only = data[operation].get('creator-only')
            user_ids = data[operation].get('users')
            s_acl = None
            if operation in existing_acls_map:  # update if matching acl exists
                s_acl = existing_acls_map[operation]
                if creator_only is not None:
                    s_acl.creator_only = creator_only
            else:
                s_acl = models.SecretACL(self.secret.id, operation=operation,
                                         creator_only=creator_only)
            self.acl_repo.create_or_replace_from(self.secret, secret_acl=s_acl,
                                                 user_ids=user_ids)

        return self._return_acl_hrefs(self.secret.id)

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) deletion'))
    @controllers.enforce_rbac('secret_acls:delete')
    def on_delete(self, external_project_id, **kwargs):

        count = self.acl_repo.get_count(self.secret.id)
        if count == 0:
            _acls_not_found("secret")
        self.acl_repo.delete_acls_for_secret(self.secret)

    def _return_acl_hrefs(self, secret_id):
        result = self.acl_repo.get_by_secret_id(secret_id)

        if not result:
            _acls_not_found("secret")
        else:
            acl_recs = [hrefs.convert_acl_to_hrefs(acl.to_dict_fields())
                        for acl in result]
            return [{'acl_ref': acl['acl_ref']} for acl in acl_recs]


class ContainerACLController(controllers.ACLMixin):
    """Handles a ContainerACL entity retrieval and update requests."""

    def __init__(self, acl_id, container_project_id, container):
        self.acl_id = acl_id
        self.container_project_id = container_project_id
        self.container = container
        self.acl_repo = repo.get_container_acl_repository()
        self.validator = validators.ACLValidator()

    def get_acl_tuple(self, req, **kwargs):
        d = {'project_id': self.container_project_id}
        return 'container', d

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerACL retrieval'))
    @controllers.enforce_rbac('container_acl:get')
    def on_get(self, external_project_id):
        container_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)

        if not container_acl:
            _acl_not_found()

        dict_fields = container_acl.to_dict_fields()

        return hrefs.convert_acl_to_hrefs(dict_fields)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('A ContainerACL Update'))
    @controllers.enforce_rbac('container_acl:patch')
    @controllers.enforce_content_types(['application/json'])
    def on_patch(self, external_project_id, **kwargs):
        """Handles existing container ACL update for given acl id."""
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start ContainerACLController on_patch...%s', data)

        container_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)
        if not container_acl:
            _acl_not_found()

        # Make sure request acl operation matches with acl stored in db
        operation = container_acl.operation
        input_acl = data.get(operation)
        if not input_acl:
            _acl_operation_update_not_allowed()

        creator_only = input_acl.get('creator-only')
        user_ids = input_acl.get('users')
        if creator_only is not None:
            container_acl.creator_only = creator_only

        self.acl_repo.create_or_replace_from(self.container,
                                             container_acl=container_acl,
                                             user_ids=user_ids)
        acl_ref = hrefs.convert_acl_to_hrefs(container_acl.to_dict_fields())

        return {'acl_ref': acl_ref['acl_ref']}

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerACL deletion'))
    @controllers.enforce_rbac('container_acl:delete')
    def on_delete(self, external_project_id, **kwargs):
        """Deletes existing ACL by acl_id provided in URI."""

        container_acl = self.acl_repo.get(
            entity_id=self.acl_id,
            suppress_exception=True)
        if not container_acl:
            _acl_not_found()

        self.acl_repo.delete_entity_by_id(entity_id=self.acl_id,
                                          external_project_id=None)


class ContainerACLsController(controllers.ACLMixin):
    """Handles ContainerACL requests by a given container id."""

    def __init__(self, container_id):
        self.container_id = container_id
        self.container = None
        self.acl_repo = repo.get_container_acl_repository()
        self.container_repo = repo.get_container_repository()
        self.validator = validators.ACLValidator()
        self.container_project_id = None

    def get_acl_tuple(self, req, **kwargs):
        self._assert_id_and_set_container(suppress_exception=True)
        d = {'project_id': self.container_project_id}
        return 'container', d

    @pecan.expose()
    def _lookup(self, acl_id, *remainder):
        self._assert_id_and_set_container()
        return (ContainerACLController(acl_id, self.container_project_id,
                                       self.container), remainder)

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) retrieval'))
    @controllers.enforce_rbac('container_acls:get')
    def on_get(self, external_project_id, **kw):
        self._assert_id_and_set_container(suppress_exception=True)
        LOG.debug('Start container ACL on_get '
                  'for container-ID %s:', self.container_id)
        if not self.container:
            controllers.containers.container_not_found()

        return self._return_acl_hrefs(self.container.id)

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) creation'))
    @controllers.enforce_rbac('container_acls:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        """Handles container acls creation request.

        Once a set of ACLs exists for a given container, it can only be updated
        via PATCH method. In create, multiple operation ACL payload can be
        specified as mentioned in sample below.

        {
          "read":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a"
            ]
          },
          "write":{
            "users":[
              "20b63d71f90848cf827ee48074f213b7",
              "5ecb18f341894e94baca9e8c7b6a824a"
            ],
            "creator-only":false
          }
        }
        """
        self._assert_id_and_set_container()

        count = self.acl_repo.get_count(self.container.id)
        LOG.debug('Count of existing ACL on_post is [%s] '
                  ' for container-ID %s:', count, self.container.id)
        if count > 0:
            _acls_already_exist()

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start ContainerACLsController on_post...%s', data)

        for operation in itertools.ifilter(lambda x: data.get(x),
                                           validators.ACL_OPERATIONS):
            in_cr_only = data[operation].get('creator-only')
            creator_only = True if in_cr_only else False
            new_acl = models.ContainerACL(self.container.id,
                                          operation=operation,
                                          creator_only=creator_only)
            self.acl_repo.create_or_replace_from(
                self.container, container_acl=new_acl,
                user_ids=data[operation].get('users'))

        pecan.response.status = 201
        return self._return_acl_hrefs(self.container.id)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) Update'))
    @controllers.enforce_rbac('container_acls:patch')
    @controllers.enforce_content_types(['application/json'])
    def on_patch(self, external_project_id, **kwargs):
        """Handles update of existing container acl requests.

        At least one container ACL needs to exist for update to proceed.
        In update, multiple operation ACL payload can be specified as
        mentioned in sample below. A specific ACL can be updated by its
        own id via ContainerACLController patch request.

        {
          "read":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a",
              "20b63d71f90848cf827ee48074f213b7",
              "c7753f8da8dc4fbea75730ab0b6e0ef4"
            ]
          },
          "write":{
            "users":[
              "5ecb18f341894e94baca9e8c7b6a824a"
            ],
            "creator-only":true
          }
        }
        """
        self._assert_id_and_set_container()
        count = self.acl_repo.get_count(self.container.id)
        LOG.debug('Count of existing ACL on_patch is [%s] '
                  ' for container-ID %s:', count, self.container.id)
        if count == 0:
            _acls_not_found("container")

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start ContainerACLsController on_patch...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.container.container_acls}
        for operation in itertools.ifilter(lambda x: data.get(x),
                                           validators.ACL_OPERATIONS):
            creator_only = data[operation].get('creator-only')
            user_ids = data[operation].get('users')
            if operation in existing_acls_map:  # update if matching acl exists
                c_acl = existing_acls_map[operation]
                if creator_only is not None:
                    c_acl.creator_only = creator_only
            else:
                c_acl = models.ContainerACL(self.container.id,
                                            operation=operation,
                                            creator_only=creator_only)
            self.acl_repo.create_or_replace_from(self.container,
                                                 container_acl=c_acl,
                                                 user_ids=user_ids)

        return self._return_acl_hrefs(self.container.id)

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) deletion'))
    @controllers.enforce_rbac('container_acls:delete')
    def on_delete(self, external_project_id, **kwargs):

        self._assert_id_and_set_container()
        count = self.acl_repo.get_count(self.container_id)
        if count == 0:
            _acls_not_found("container")

        self.acl_repo.delete_acls_for_container(self.container)

    def _assert_id_and_set_container(self, suppress_exception=False):
        """Checks whether container_id is valid or not.

        Whether container is associated with token's project is not needed as
        that check is now made via policy rule.
        """
        if self.container:
            return
        controllers.assert_is_valid_uuid_from_uri(self.container_id)
        self.container = self.container_repo.get_container_by_id(
            entity_id=self.container_id, suppress_exception=True)
        if not self.container and not suppress_exception:
            controllers.containers.container_not_found()
        if self.container:
            self.container_project_id = self.container.project.external_id

    def _return_acl_hrefs(self, container_id):
        result = self.acl_repo.get_by_container_id(container_id)

        if not result:
            _acls_not_found("container")
        else:
            acl_recs = [hrefs.convert_acl_to_hrefs(acl.to_dict_fields())
                        for acl in result]
            return [{'acl_ref': acl['acl_ref']} for acl in acl_recs]
