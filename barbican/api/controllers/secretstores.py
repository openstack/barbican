# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
#
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

from barbican.api import controllers
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.common import utils
from barbican import i18n as u
from barbican.model import repositories as repo
from barbican.plugin.util import multiple_backends

LOG = utils.getLogger(__name__)


def _secret_store_not_found():
    """Throw exception indicating secret store not found."""
    pecan.abort(404, u._('Not Found. Secret store not found.'))


def _preferred_secret_store_not_found():
    """Throw exception indicating preferred secret store not found."""
    pecan.abort(404, u._('Not Found. No preferred secret store defined for '
                         'this project.'))


def _multiple_backends_not_enabled():
    """Throw exception indicating multiple backends support is not enabled."""
    pecan.abort(404, u._('Not Found. Multiple backends support is not enabled '
                         'in service configuration.'))


def convert_secret_store_to_response_format(secret_store):
    data = secret_store.to_dict_fields()
    data['secret_store_plugin'] = data.pop('store_plugin')
    data['secret_store_ref'] = hrefs.convert_secret_stores_to_href(
        data['secret_store_id'])
    # no need to pass store id as secret_store_ref is returned
    data.pop('secret_store_id', None)
    return data


class PreferredSecretStoreController(controllers.ACLMixin):
    """Handles preferred secret store set/removal requests."""

    def __init__(self, secret_store):
        LOG.debug('=== Creating PreferredSecretStoreController ===')
        super().__init__()
        self.secret_store = secret_store
        self.proj_store_repo = repo.get_project_secret_store_repository()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='DELETE', template='json')
    @controllers.handle_exceptions(u._('Removing preferred secret store'))
    @controllers.enforce_rbac('secretstore_preferred:delete')
    def on_delete(self, external_project_id, **kw):
        LOG.debug('Start: Remove project preferred secret-store for store'
                  ' id %s', self.secret_store.id)

        project = res.get_or_create_project(external_project_id)

        project_store = self.proj_store_repo.get_secret_store_for_project(
            project.id, None, suppress_exception=True)
        if project_store is None:
            _preferred_secret_store_not_found()

        self.proj_store_repo.delete_entity_by_id(
            entity_id=project_store.id,
            external_project_id=external_project_id)
        pecan.response.status = 204

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Setting preferred secret store'))
    @controllers.enforce_rbac('secretstore_preferred:post')
    def on_post(self, external_project_id, **kwargs):
        LOG.debug('Start: Set project preferred secret-store for store '
                  'id %s', self.secret_store.id)

        project = res.get_or_create_project(external_project_id)

        self.proj_store_repo.create_or_update_for_project(project.id,
                                                          self.secret_store.id)

        pecan.response.status = 204


class SecretStoreController(controllers.ACLMixin):
    """Handles secret store retrieval requests."""

    def __init__(self, secret_store):
        LOG.debug('=== Creating SecretStoreController ===')
        super().__init__()
        self.secret_store = secret_store

    @pecan.expose()
    def _lookup(self, action, *remainder):
        if (action == 'preferred'):
            return PreferredSecretStoreController(self.secret_store), remainder
        else:
            pecan.abort(405)

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Secret store retrieval'))
    @controllers.enforce_rbac('secretstore:get')
    def on_get(self, external_project_id):
        LOG.debug("== Getting secret store for %s", self.secret_store.id)
        return convert_secret_store_to_response_format(self.secret_store)


class SecretStoresController(controllers.ACLMixin):
    """Handles secret-stores list requests."""

    def __init__(self):
        LOG.debug('Creating SecretStoresController')
        super().__init__()
        self.secret_stores_repo = repo.get_secret_stores_repository()
        self.proj_store_repo = repo.get_project_secret_store_repository()

    def __getattr__(self, name):
        route_table = {
            'global-default': self.get_global_default,
            'preferred': self.get_preferred,
        }
        if name in route_table:
            return route_table[name]
        raise AttributeError

    @pecan.expose()
    def _lookup(self, secret_store_id, *remainder):
        if not utils.is_multiple_backends_enabled():
            _multiple_backends_not_enabled()

        secret_store = self.secret_stores_repo.get(entity_id=secret_store_id,
                                                   suppress_exception=True)
        if not secret_store:
            _secret_store_not_found()
        return SecretStoreController(secret_store), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('List available secret stores'))
    @controllers.enforce_rbac('secretstores:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start SecretStoresController on_get: listing secret '
                  'stores')
        if not utils.is_multiple_backends_enabled():
            _multiple_backends_not_enabled()

        res.get_or_create_project(external_project_id)

        secret_stores = self.secret_stores_repo.get_all()

        resp_list = []
        for store in secret_stores:
            item = convert_secret_store_to_response_format(store)
            resp_list.append(item)

        resp = {'secret_stores': resp_list}

        return resp

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Retrieve global default secret store'))
    @controllers.enforce_rbac('secretstores:get_global_default')
    def get_global_default(self, external_project_id, **kw):
        LOG.debug('Start secret-stores get global default secret store')

        if not utils.is_multiple_backends_enabled():
            _multiple_backends_not_enabled()

        res.get_or_create_project(external_project_id)

        store = multiple_backends.get_global_default_secret_store()

        return convert_secret_store_to_response_format(store)

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Retrieve project preferred store'))
    @controllers.enforce_rbac('secretstores:get_preferred')
    def get_preferred(self, external_project_id, **kw):
        LOG.debug('Start secret-stores get preferred secret store')

        if not utils.is_multiple_backends_enabled():
            _multiple_backends_not_enabled()

        project = res.get_or_create_project(external_project_id)

        project_store = self.proj_store_repo.get_secret_store_for_project(
            project.id, None, suppress_exception=True)

        if project_store is None:
            _preferred_secret_store_not_found()

        return convert_secret_store_to_response_format(
            project_store.secret_store)
