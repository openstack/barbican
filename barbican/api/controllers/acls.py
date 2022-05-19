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
from barbican.common import hrefs
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo

LOG = utils.getLogger(__name__)


def _convert_acl_to_response_format(acl, acls_dict):
    fields = acl.to_dict_fields()
    operation = fields['operation']

    acl_data = {}  # dict for each acl operation data

    acl_data['project-access'] = fields['project_access']
    acl_data['users'] = fields.get('users', [])
    acl_data['created'] = fields['created']
    acl_data['updated'] = fields['updated']

    acls_dict[operation] = acl_data


DEFAULT_ACL = {'read': {'project-access': True}}


class SecretACLsController(controllers.ACLMixin):
    """Handles SecretACL requests by a given secret id."""

    def __init__(self, secret):
        super().__init__()
        self.secret = secret
        self.secret_project_id = self.secret.project.external_id
        self.acl_repo = repo.get_secret_acl_repository()
        self.validator = validators.ACLValidator()

    def get_acl_tuple(self, req, **kwargs):
        d = {'project_id': self.secret_project_id,
             'creator_id': self.secret.creator_id}
        return 'secret', d

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) retrieval'))
    @controllers.enforce_rbac('secret_acls:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start secret ACL on_get '
                  'for secret-ID %s:', self.secret.id)

        return self._return_acl_list_response(self.secret.id)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) Update'))
    @controllers.enforce_rbac('secret_acls:put_patch')
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
            "project-access":true
          }
        }
        """
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_patch...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.secret.secret_acls}
        for operation in filter(lambda x: data.get(x),
                                validators.ACL_OPERATIONS):
            project_access = data[operation].get('project-access')
            user_ids = data[operation].get('users')
            s_acl = None
            if operation in existing_acls_map:  # update if matching acl exists
                s_acl = existing_acls_map[operation]
                if project_access is not None:
                    s_acl.project_access = project_access
            else:
                s_acl = models.SecretACL(self.secret.id, operation=operation,
                                         project_access=project_access)
            self.acl_repo.create_or_replace_from(self.secret, secret_acl=s_acl,
                                                 user_ids=user_ids)

        acl_ref = '{0}/acl'.format(
            hrefs.convert_secret_to_href(self.secret.id))
        return {'acl_ref': acl_ref}

    @index.when(method='PUT', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) Update'))
    @controllers.enforce_rbac('secret_acls:put_patch')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, external_project_id, **kwargs):
        """Handles update of existing secret acl requests.

        Replaces existing secret ACL(s) with input ACL(s) data. Existing
        ACL operation not specified in input are removed as part of update.
        For missing project-access in ACL, true is used as default.
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
            "project-access":false
          }
        }

        Every secret, by default, has an implicit ACL in case client has not
        defined an explicit ACL. That default ACL definition, DEFAULT_ACL,
        signifies that a secret by default has project based access i.e. client
        with necessary roles on secret project can access the secret. That's
        why when ACL is added to a secret, it always returns 200 (and not 201)
        indicating existence of implicit ACL on a secret.
        """
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_put...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.secret.secret_acls}
        for operation in filter(lambda x: data.get(x),
                                validators.ACL_OPERATIONS):
            project_access = data[operation].get('project-access', True)
            user_ids = data[operation].get('users', [])
            s_acl = None
            if operation in existing_acls_map:  # update if matching acl exists
                s_acl = existing_acls_map.pop(operation)
                s_acl.project_access = project_access
            else:
                s_acl = models.SecretACL(self.secret.id, operation=operation,
                                         project_access=project_access)
            self.acl_repo.create_or_replace_from(self.secret, secret_acl=s_acl,
                                                 user_ids=user_ids)
        # delete remaining existing acls as they are not present in input.
        for acl in existing_acls_map.values():
            self.acl_repo.delete_entity_by_id(entity_id=acl.id,
                                              external_project_id=None)
        acl_ref = '{0}/acl'.format(
            hrefs.convert_secret_to_href(self.secret.id))
        return {'acl_ref': acl_ref}

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('SecretACL(s) deletion'))
    @controllers.enforce_rbac('secret_acls:delete')
    def on_delete(self, external_project_id, **kwargs):

        count = self.acl_repo.get_count(self.secret.id)
        if count > 0:
            self.acl_repo.delete_acls_for_secret(self.secret)

    def _return_acl_list_response(self, secret_id):
        result = self.acl_repo.get_by_secret_id(secret_id)

        acls_data = {}
        if result:
            for acl in result:
                _convert_acl_to_response_format(acl, acls_data)
        if not acls_data:
            acls_data = DEFAULT_ACL.copy()
        return acls_data


class ContainerACLsController(controllers.ACLMixin):
    """Handles ContainerACL requests by a given container id."""

    def __init__(self, container):
        super().__init__()
        self.container = container
        self.container_id = container.id
        self.acl_repo = repo.get_container_acl_repository()
        self.container_repo = repo.get_container_repository()
        self.validator = validators.ACLValidator()
        self.container_project_id = container.project.external_id

    def get_acl_tuple(self, req, **kwargs):
        d = {'project_id': self.container_project_id,
             'creator_id': self.container.creator_id}
        return 'container', d

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) retrieval'))
    @controllers.enforce_rbac('container_acls:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start container ACL on_get '
                  'for container-ID %s:', self.container_id)

        return self._return_acl_list_response(self.container.id)

    @index.when(method='PATCH', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) Update'))
    @controllers.enforce_rbac('container_acls:put_patch')
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
            "project-access":false
          }
        }
        """
        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start ContainerACLsController on_patch...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.container.container_acls}
        for operation in filter(lambda x: data.get(x),
                                validators.ACL_OPERATIONS):
            project_access = data[operation].get('project-access')
            user_ids = data[operation].get('users')
            if operation in existing_acls_map:  # update if matching acl exists
                c_acl = existing_acls_map[operation]
                if project_access is not None:
                    c_acl.project_access = project_access
            else:
                c_acl = models.ContainerACL(self.container.id,
                                            operation=operation,
                                            project_access=project_access)
            self.acl_repo.create_or_replace_from(self.container,
                                                 container_acl=c_acl,
                                                 user_ids=user_ids)

        acl_ref = '{0}/acl'.format(
            hrefs.convert_container_to_href(self.container.id))
        return {'acl_ref': acl_ref}

    @index.when(method='PUT', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) Update'))
    @controllers.enforce_rbac('container_acls:put_patch')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, external_project_id, **kwargs):
        """Handles update of existing container acl requests.

        Replaces existing container ACL(s) with input ACL(s) data. Existing
        ACL operation not specified in input are removed as part of update.
        For missing project-access in ACL, true is used as default.
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
            "project-access":false
          }
        }

        Every container, by default, has an implicit ACL in case client has not
        defined an explicit ACL. That default ACL definition, DEFAULT_ACL,
        signifies that a container by default has project based access i.e.
        client with necessary roles on container project can access the
        container. That's why when ACL is added to a container, it always
        returns 200 (and not 201) indicating existence of implicit ACL on a
        container.
        """

        data = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start ContainerACLsController on_put...%s', data)

        existing_acls_map = {acl.operation: acl for acl in
                             self.container.container_acls}
        for operation in filter(lambda x: data.get(x),
                                validators.ACL_OPERATIONS):
            project_access = data[operation].get('project-access', True)
            user_ids = data[operation].get('users', [])
            if operation in existing_acls_map:  # update if matching acl exists
                c_acl = existing_acls_map.pop(operation)
                c_acl.project_access = project_access
            else:
                c_acl = models.ContainerACL(self.container.id,
                                            operation=operation,
                                            project_access=project_access)
            self.acl_repo.create_or_replace_from(self.container,
                                                 container_acl=c_acl,
                                                 user_ids=user_ids)
        # delete remaining existing acls as they are not present in input.
        for acl in existing_acls_map.values():
            self.acl_repo.delete_entity_by_id(entity_id=acl.id,
                                              external_project_id=None)
        acl_ref = '{0}/acl'.format(
            hrefs.convert_container_to_href(self.container.id))
        return {'acl_ref': acl_ref}

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('ContainerACL(s) deletion'))
    @controllers.enforce_rbac('container_acls:delete')
    def on_delete(self, external_project_id, **kwargs):
        count = self.acl_repo.get_count(self.container_id)
        if count > 0:
            self.acl_repo.delete_acls_for_container(self.container)

    def _return_acl_list_response(self, container_id):
        result = self.acl_repo.get_by_container_id(container_id)

        acls_data = {}
        if result:
            for acl in result:
                _convert_acl_to_response_format(acl, acls_data)
        if not acls_data:
            acls_data = DEFAULT_ACL.copy()
        return acls_data
