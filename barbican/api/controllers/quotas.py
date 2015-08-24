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
from barbican.common import exception
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u


LOG = utils.getLogger(__name__)


def _project_quotas_not_found():
    """Throw exception indicating project quotas not found."""
    pecan.abort(404, u._('Not Found. Sorry but your project quotas are in '
                         'another castle.'))


class QuotasController(controllers.ACLMixin):
    """Handles quota retrieval requests."""

    def __init__(self):
        LOG.debug('=== Creating QuotasController ===')
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Quotas'))
    @controllers.enforce_rbac('quotas:get')
    def on_get(self, external_project_id, **kwargs):
        LOG.debug('=== QuotasController GET ===')
        # make sure project exists
        res.get_or_create_project(external_project_id)
        resp = self.quota_driver.get_quotas(external_project_id)
        return resp


class ProjectQuotasController(controllers.ACLMixin):
    """Handles project quota requests."""

    def __init__(self, project_id):
        LOG.debug('=== Creating ProjectQuotasController ===')
        self.passed_project_id = project_id
        self.validator = validators.ProjectQuotaValidator()
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:get')
    def on_get(self, external_project_id, **kwargs):
        LOG.debug('=== ProjectQuotasController GET ===')
        resp = self.quota_driver.get_project_quotas(self.passed_project_id)
        if resp:
            return resp
        else:
            _project_quotas_not_found()

    @index.when(method='PUT', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:put')
    def on_put(self, external_project_id, **kwargs):
        LOG.debug('=== ProjectQuotasController PUT ===')
        if not pecan.request.body:
            raise exception.NoDataToProcess()
        api.load_body(pecan.request,
                      validator=self.validator)
        self.quota_driver.set_project_quotas(self.passed_project_id,
                                             kwargs['project_quotas'])
        LOG.info(u._LI('Put Project Quotas'))
        pecan.response.status = 204

    @index.when(method='DELETE', template='json')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:delete')
    def on_delete(self, external_project_id, **kwargs):
        LOG.debug('=== ProjectQuotasController DELETE ===')
        try:
            self.quota_driver.delete_project_quotas(self.passed_project_id)
        except exception.NotFound:
            LOG.info(u._LI('Delete Project Quotas - Project not found'))
            _project_quotas_not_found()
        else:
            LOG.info(u._LI('Delete Project Quotas'))
            pecan.response.status = 204


class ProjectsQuotasController(controllers.ACLMixin):
    """Handles projects quota retrieval requests."""

    def __init__(self):
        LOG.debug('=== Creating ProjectsQuotaController ===')
        self.quota_driver = quota.QuotaDriver()

    @pecan.expose()
    def _lookup(self, project_id, *remainder):
        return ProjectQuotasController(project_id), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Project Quotas'))
    @controllers.enforce_rbac('project_quotas:get')
    def on_get(self, external_project_id, **kwargs):
        resp = self.quota_driver.get_project_quotas_list(
            offset_arg=kwargs.get('offset', 0),
            limit_arg=kwargs.get('limit', None)
        )
        return resp
