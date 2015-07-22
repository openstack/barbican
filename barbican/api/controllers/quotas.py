# Copyright (c) 2015 Cisco Systems
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

from barbican import api
from barbican.api import controllers
from barbican.common import quota
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u

LOG = utils.getLogger(__name__)


class QuotasController(controllers.ACLMixin):
    """Handles quota retrieval requests."""

    def __init__(self, quota_repo=None):
        LOG.debug('=== Creating QuotasController ===')
        self.repo = quota_repo
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Quotas'))
    @controllers.enforce_rbac('quotas:get')
    def on_get(self, external_project_id, **kwargs):
        # TODO(dave) implement
        resp = {'quotas': self.quota_driver.get_defaults()}
        return resp


class ProjectQuotasController(controllers.ACLMixin):
    """Handles project quota requests."""

    def __init__(self, project_id, project_quota_repo=None):
        LOG.debug('=== Creating ProjectQuotasController ===')
        self.passed_project_id = project_id
        self.repo = project_quota_repo
        self.validator = validators.ProjectQuotaValidator()
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:get')
    def on_get(self, external_project_id, **kwargs):
        # TODO(dave) implement
        LOG.debug('=== ProjectQuotasController GET ===')
        resp = {'project_quotas': self.quota_driver.get_defaults()}

        return resp

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:post')
    def on_post(self, external_project_id, **kwargs):
        LOG.debug('=== ProjectQuotasController POST ===')
        api.load_body(pecan.request,
                      validator=self.validator)
        # TODO(dave) implement
        resp = {'project_quotas': {
            'secrets': 10,
            'orders': 20,
            'containers': 10,
            'transport_keys': 10,
            'consumers': -1}
        }
        LOG.info(u._LI('Post Project Quotas'))
        return resp

    @index.when(method='DELETE', template='json')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:delete')
    def on_delete(self, external_project_id, **kwargs):
        LOG.debug('=== ProjectQuotasController DELETE ===')
        # TODO(dave) implement
        LOG.info(u._LI('Delete Project Quotas'))
        pecan.response.status = 204


class ProjectsQuotasController(controllers.ACLMixin):
    """Handles projects quota retrieval requests."""

    def __init__(self, project_quota_repo=None):
        LOG.debug('=== Creating ProjectsQuotaController ===')
        self.repo = project_quota_repo
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose()
    def _lookup(self, project_id, *remainder):
        return ProjectQuotasController(project_id,
                                       project_quota_repo=self.repo), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:get')
    def on_get(self, external_project_id, **kwargs):

        # TODO(dave) implement
        project1 = {'project_id': "1234",
                    'project_quotas': self.quota_driver.get_defaults()}
        project2 = {'project_id': "5678",
                    'project_quotas': self.quota_driver.get_defaults()}
        project_quotas = {"project_quotas": [project1, project2]}
        resp = project_quotas

        return resp
