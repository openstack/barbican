# Copyright (c) 2014 Red Hat, Inc.
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
from six.moves.urllib import parse

from barbican import api
from barbican.api import controllers
from barbican.common import exception as excep
from barbican.common import hrefs
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.tasks import certificate_resources as cert_resources

LOG = utils.getLogger(__name__)


def _certificate_authority_not_found():
    """Throw exception indicating certificate authority not found."""
    pecan.abort(404, u._('Not Found. CA not found.'))


def _certificate_authority_attribute_not_found():
    """Throw exception indicating CA attribute was not found."""
    pecan.abort(404, u._('Not Found. CA attribute not found.'))


def _ca_not_in_project():
    """Throw exception certificate authority is not in project."""
    pecan.abort(404, u._('Not Found. CA not in project.'))


def _requested_preferred_ca_not_a_project_ca():
    """Throw exception indicating that preferred CA is not a project CA."""
    pecan.abort(
        400,
        u._('Cannot set CA as a preferred CA as it is not a project CA.')
    )


def _cant_remove_preferred_ca_from_project():
    pecan.abort(
        409,
        u._('Please change the preferred CA to a different project CA '
            'before removing it.')
    )


class CertificateAuthorityController(controllers.ACLMixin):
    """Handles certificate authority retrieval requests."""

    def __init__(self, ca):
        LOG.debug('=== Creating CertificateAuthorityController ===')
        self.ca = ca
        self.ca_repo = repo.get_ca_repository()
        self.project_ca_repo = repo.get_project_ca_repository()
        self.preferred_ca_repo = repo.get_preferred_ca_repository()
        self.project_repo = repo.get_project_repository()

    def __getattr__(self, name):
        route_table = {
            'add-to-project': self.add_to_project,
            'remove-from-project': self.remove_from_project,
            'set-global-preferred': self.set_global_preferred,
            'set-preferred': self.set_preferred,
        }
        if name in route_table:
            return route_table[name]
        raise AttributeError

    @pecan.expose()
    def _lookup(self, attribute, *remainder):
        _certificate_authority_attribute_not_found()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Certificate Authority retrieval'))
    @controllers.enforce_rbac('certificate_authority:get')
    def on_get(self, external_project_id):
        LOG.debug("== Getting certificate authority for %s", self.ca.id)
        return self.ca.to_dict_fields()

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('CA Signing Cert retrieval'))
    @controllers.enforce_rbac('certificate_authority:get_cacert')
    def cacert(self, external_project_id):
        LOG.debug("== Getting signing cert for %s", self.ca.id)
        cacert = self.ca.ca_meta['ca_signing_certificate'].value
        return cacert

    @pecan.expose()
    @controllers.handle_exceptions(u._('CA Cert Chain retrieval'))
    @controllers.enforce_rbac('certificate_authority:get_ca_cert_chain')
    def intermediates(self, external_project_id):
        LOG.debug("== Getting CA Cert Chain for %s", self.ca.id)
        cert_chain = self.ca.ca_meta['intermediates'].value
        return cert_chain

    @pecan.expose(template='json')
    @controllers.handle_exceptions(u._('CA projects retrieval'))
    @controllers.enforce_rbac('certificate_authority:get_projects')
    def projects(self, external_project_id):
        LOG.debug("== Getting Projects for %s", self.ca.id)
        project_cas = self.ca.project_cas
        if not project_cas:
            ca_projects_resp = {'projects': []}
        else:
            project_list = []
            for p in project_cas:
                project_list.append(p.project.external_id)

            ca_projects_resp = {'projects': project_list}

        return ca_projects_resp

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Add CA to project'))
    @controllers.enforce_rbac('certificate_authority:add_to_project')
    def add_to_project(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Saving CA %s to external_project_id %s",
                  self.ca.id, external_project_id)
        project_model = res.get_or_create_project(external_project_id)

        # CA must be a base CA or a subCA owned by this project
        if (self.ca.project_id is not None and
                self.ca.project_id != project_model.id):
            raise excep.UnauthorizedSubCA()

        project_cas = project_model.cas
        num_cas = len(project_cas)
        for project_ca in project_cas:
            if project_ca.ca_id == self.ca.id:
                # project already added
                return

        project_ca = models.ProjectCertificateAuthority(
            project_model.id, self.ca.id)
        self.project_ca_repo.create_from(project_ca)

        if num_cas == 0:
            # set first project CA to be the preferred one
            preferred_ca = models.PreferredCertificateAuthority(
                project_model.id, self.ca.id)
            self.preferred_ca_repo.create_from(preferred_ca)

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Remove CA from project'))
    @controllers.enforce_rbac('certificate_authority:remove_from_project')
    def remove_from_project(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Removing CA %s from project_external_id %s",
                  self.ca.id, external_project_id)

        project_model = res.get_or_create_project(external_project_id)
        (project_ca, __offset, __limit, __total) = (
            self.project_ca_repo.get_by_create_date(
                project_id=project_model.id,
                ca_id=self.ca.id,
                suppress_exception=True))

        if project_ca:
            self._do_remove_from_project(project_ca[0])
        else:
            _ca_not_in_project()

    def _do_remove_from_project(self, project_ca):
        project_id = project_ca.project_id
        ca_id = project_ca.ca_id
        preferred_ca = self.preferred_ca_repo.get_project_entities(
            project_id)[0]
        if cert_resources.is_last_project_ca(project_id):
            self.preferred_ca_repo.delete_entity_by_id(preferred_ca.id, None)
        else:
            self._assert_is_not_preferred_ca(preferred_ca.ca_id, ca_id)

        self.project_ca_repo.delete_entity_by_id(project_ca.id, None)

    def _assert_is_not_preferred_ca(self, preferred_ca_id, ca_id):
        if preferred_ca_id == ca_id:
            _cant_remove_preferred_ca_from_project()

    @pecan.expose()
    @controllers.handle_exceptions(u._('Set preferred project CA'))
    @controllers.enforce_rbac('certificate_authority:set_preferred')
    def set_preferred(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Setting preferred CA %s for project %s",
                  self.ca.id, external_project_id)

        project_model = res.get_or_create_project(external_project_id)

        (project_ca, __offset, __limit, __total) = (
            self.project_ca_repo.get_by_create_date(
                project_id=project_model.id,
                ca_id=self.ca.id,
                suppress_exception=True))
        if not project_ca:
            _requested_preferred_ca_not_a_project_ca()

        self.preferred_ca_repo.create_or_update_by_project_id(
            project_model.id, self.ca.id)

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Set global preferred CA'))
    @controllers.enforce_rbac('certificate_authority:set_global_preferred')
    def set_global_preferred(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Set global preferred CA %s", self.ca.id)
        project = res.get_or_create_global_preferred_project()
        self.preferred_ca_repo.create_or_update_by_project_id(
            project.id, self.ca.id)

    @index.when(method='DELETE')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('CA deletion'))
    @controllers.enforce_rbac('certificate_authority:delete')
    def on_delete(self, external_project_id, **kwargs):
        cert_resources.delete_subordinate_ca(external_project_id, self.ca)
        LOG.info(u._LI('Deleted CA for project: %s'), external_project_id)


class CertificateAuthoritiesController(controllers.ACLMixin):
    """Handles certificate authority list requests."""

    def __init__(self):
        LOG.debug('Creating CertificateAuthoritiesController')
        self.ca_repo = repo.get_ca_repository()
        self.project_ca_repo = repo.get_project_ca_repository()
        self.preferred_ca_repo = repo.get_preferred_ca_repository()
        self.project_repo = repo.get_project_repository()
        self.validator = validators.NewCAValidator()
        self.quota_enforcer = quota.QuotaEnforcer('cas', self.ca_repo)
        # Populate the CA table at start up
        cert_resources.refresh_certificate_resources()

    def __getattr__(self, name):
        route_table = {
            'all': self.get_all,
            'global-preferred': self.get_global_preferred,
            'preferred': self.preferred,
            'unset-global-preferred': self.unset_global_preferred,
        }
        if name in route_table:
            return route_table[name]
        raise AttributeError

    @pecan.expose()
    def _lookup(self, ca_id, *remainder):
        ca = self.ca_repo.get(entity_id=ca_id, suppress_exception=True)
        if not ca:
            _certificate_authority_not_found()
        return CertificateAuthorityController(ca), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(
        u._('Certificate Authorities retrieval (limited)'))
    @controllers.enforce_rbac('certificate_authorities:get_limited')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities on_get (limited)')

        plugin_name = kw.get('plugin_name')
        if plugin_name is not None:
            plugin_name = parse.unquote_plus(plugin_name)

        plugin_ca_id = kw.get('plugin_ca_id', None)
        if plugin_ca_id is not None:
            plugin_ca_id = parse.unquote_plus(plugin_ca_id)

        # refresh CA table, in case plugin entries have expired
        cert_resources.refresh_certificate_resources()

        project_model = res.get_or_create_project(external_project_id)

        if self._project_cas_defined(project_model.id):
            cas, offset, limit, total = self._get_subcas_and_project_cas(
                offset=kw.get('offset', 0),
                limit=kw.get('limit', None),
                plugin_name=plugin_name,
                plugin_ca_id=plugin_ca_id,
                project_id=project_model.id)
        else:
            cas, offset, limit, total = self._get_subcas_and_root_cas(
                offset=kw.get('offset', 0),
                limit=kw.get('limit', None),
                plugin_name=plugin_name,
                plugin_ca_id=plugin_ca_id,
                project_id=project_model.id)

        return self._display_cas(cas, offset, limit, total)

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Certificate Authorities retrieval'))
    @controllers.enforce_rbac('certificate_authorities:get')
    def get_all(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities on_get')

        plugin_name = kw.get('plugin_name')
        if plugin_name is not None:
            plugin_name = parse.unquote_plus(plugin_name)

        plugin_ca_id = kw.get('plugin_ca_id', None)
        if plugin_ca_id is not None:
            plugin_ca_id = parse.unquote_plus(plugin_ca_id)

        # refresh CA table, in case plugin entries have expired
        cert_resources.refresh_certificate_resources()

        project_model = res.get_or_create_project(external_project_id)

        cas, offset, limit, total = self._get_subcas_and_root_cas(
            offset=kw.get('offset', 0),
            limit=kw.get('limit', None),
            plugin_name=plugin_name,
            plugin_ca_id=plugin_ca_id,
            project_id=project_model.id)

        return self._display_cas(cas, offset, limit, total)

    def _get_project_cas(self, project_id, query_filters):
        cas, offset, limit, total = self.project_ca_repo.get_by_create_date(
            offset_arg=query_filters.get('offset', 0),
            limit_arg=query_filters.get('limit', None),
            project_id=project_id,
            suppress_exception=True
        )
        return cas, offset, limit, total

    def _project_cas_defined(self, project_id):
        _cas, _offset, _limit, total = self._get_project_cas(project_id, {})
        return total > 0

    def _get_subcas_and_project_cas(self, offset, limit, plugin_name,
                                    plugin_ca_id, project_id):
        return self.ca_repo.get_by_create_date(
            offset_arg=offset,
            limit_arg=limit,
            plugin_name=plugin_name,
            plugin_ca_id=plugin_ca_id,
            project_id=project_id,
            restrict_to_project_cas=True,
            suppress_exception=True)

    def _get_subcas_and_root_cas(self, offset, limit, plugin_name,
                                 plugin_ca_id, project_id):
        return self.ca_repo.get_by_create_date(
            offset_arg=offset,
            limit_arg=limit,
            plugin_name=plugin_name,
            plugin_ca_id=plugin_ca_id,
            project_id=project_id,
            restrict_to_project_cas=False,
            suppress_exception=True)

    def _display_cas(self, cas, offset, limit, total):
        if not cas:
            cas_resp_overall = {'cas': [],
                                'total': total}
        else:
            cas_resp = [
                hrefs.convert_certificate_authority_to_href(ca.id)
                for ca in cas]
            cas_resp_overall = hrefs.add_nav_hrefs('cas', offset, limit, total,
                                                   {'cas': cas_resp})
            cas_resp_overall.update({'total': total})

        return cas_resp_overall

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Retrieve global preferred CA'))
    @controllers.enforce_rbac(
        'certificate_authorities:get_global_preferred_ca')
    def get_global_preferred(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities get_global_preferred CA')

        pref_ca = cert_resources.get_global_preferred_ca()
        if not pref_ca:
            pecan.abort(404, u._("No global preferred CA defined"))

        return {
            'ca_ref':
                hrefs.convert_certificate_authority_to_href(pref_ca.ca_id)
        }

    @pecan.expose()
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Unset global preferred CA'))
    @controllers.enforce_rbac('certificate_authorities:unset_global_preferred')
    def unset_global_preferred(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)
        LOG.debug("== Unsetting global preferred CA")
        self._remove_global_preferred_ca(external_project_id)

    def _remove_global_preferred_ca(self, external_project_id):
        global_preferred_ca = cert_resources.get_global_preferred_ca()
        if global_preferred_ca:
            self.preferred_ca_repo.delete_entity_by_id(
                global_preferred_ca.id,
                external_project_id)

    @pecan.expose(generic=True, template='json')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Retrieve project preferred CA'))
    @controllers.enforce_rbac('certificate_authorities:get_preferred_ca')
    def preferred(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities get project preferred CA')

        project = res.get_or_create_project(external_project_id)

        pref_ca_id = cert_resources.get_project_preferred_ca_id(project.id)
        if not pref_ca_id:
            pecan.abort(404, u._("No preferred CA defined for this project"))

        return {
            'ca_ref':
                hrefs.convert_certificate_authority_to_href(pref_ca_id)
        }

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('CA creation'))
    @controllers.enforce_rbac('certificate_authorities:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        LOG.debug('Start on_post for project-ID %s:...', external_project_id)

        data = api.load_body(pecan.request, validator=self.validator)
        project = res.get_or_create_project(external_project_id)

        ctxt = controllers._get_barbican_context(pecan.request)
        if ctxt:  # in authenticated pipeline case, always use auth token user
            creator_id = ctxt.user

        self.quota_enforcer.enforce(project)

        new_ca = cert_resources.create_subordinate_ca(
            project_model=project,
            name=data.get('name'),
            description=data.get('description'),
            subject_dn=data.get('subject_dn'),
            parent_ca_ref=data.get('parent_ca_ref'),
            creator_id=creator_id
        )

        url = hrefs.convert_certificate_authority_to_href(new_ca.id)
        LOG.debug('URI to sub-CA is %s', url)

        pecan.response.status = 201
        pecan.response.headers['Location'] = url

        LOG.info(u._LI('Created a sub CA for project: %s'),
                 external_project_id)

        return {'ca_ref': url}
