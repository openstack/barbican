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

from barbican.api import controllers
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.common import utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo

LOG = utils.getLogger(__name__)


def _certificate_authority_not_found():
    """Throw exception indicating certificate authority not found."""
    pecan.abort(404, u._('Not Found. CA not found.'))


def _requested_preferred_ca_not_a_project_ca():
    """Throw exception indicating that preferred CA is not a project CA."""
    pecan.abort(
        400,
        u._('Cannot set CA as a preferred CA as it is not a project CA.')
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
            'set-preferred': self.set_preferred,
            'set-global-preferred': self.set_global_preferred,
            'unset-global-preferred': self.unset_global_preferred,
        }
        if name in route_table:
            return route_table[name]
        raise AttributeError

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
                project_list.append(p.project_id)

            ca_projects_resp = {'projects': project_list}

        return ca_projects_resp

    @pecan.expose()
    @controllers.handle_exceptions(u._('Add CA to project'))
    @controllers.enforce_rbac('certificate_authority:add_to_project')
    def add_to_project(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Saving CA %s to external_project_id %s",
                  self.ca.id, external_project_id)
        project_model = res.get_or_create_project(external_project_id)

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
            self.project_ca_repo.delete_entity_by_id(
                project_ca[0].id,
                None)

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

        preferred_ca = self.preferred_ca_repo.get_project_entities(
            project_model.id)
        if preferred_ca is not None:
            self.preferred_ca_repo.update_preferred_ca(project_model.id,
                                                       self.ca)
        else:
            preferred_ca = models.PreferredCertificateAuthority(
                project_model.id, self.ca.id)
            self.preferred_ca_repo.create_from(preferred_ca)

    @pecan.expose()
    @controllers.handle_exceptions(u._('Set global preferred CA'))
    @controllers.enforce_rbac('certificate_authority:set_global_preferred')
    def set_global_preferred(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)

        LOG.debug("== Set global preferred CA %s", self.ca.id)
        pref_ca = self.preferred_ca_repo.get_global_preferred_ca()
        if pref_ca is None:
            global_preferred_ca = models.PreferredCertificateAuthority(
                self.preferred_ca_repo.PREFERRED_PROJECT_ID,
                self.ca.id)
            self.preferred_ca_repo.create_from(global_preferred_ca)
        else:
            self.preferred_ca_repo.update_global_preferred_ca(self.ca)

    @pecan.expose()
    @controllers.handle_exceptions(u._('Unset global preferred CA'))
    @controllers.enforce_rbac('certificate_authority:unset_global_preferred')
    def unset_global_preferred(self, external_project_id):
        if pecan.request.method != 'POST':
            pecan.abort(405)
        LOG.debug("== Unsetting global preferred CA")
        self._remove_global_preferred_ca(external_project_id)

    def _remove_global_preferred_ca(self, external_project_id):
        global_preferred_ca = self.preferred_ca_repo.get_project_entities(
            self.preferred_ca_repo.PREFERRED_PROJECT_ID)
        if global_preferred_ca:
            self.preferred_ca_repo.delete_entity_by_id(
                global_preferred_ca[0].id,
                external_project_id)


class CertificateAuthoritiesController(controllers.ACLMixin):
    """Handles certificate authority list requests."""

    def __init__(self):
        LOG.debug('Creating CertificateAuthoritiesController')
        self.ca_repo = repo.get_ca_repository()
        self.project_ca_repo = repo.get_project_ca_repository()
        self.preferred_ca_repo = repo.get_preferred_ca_repository()
        self.project_repo = repo.get_project_repository()
        self.validator = None

    def __getattr__(self, name):
        route_table = {
            'global-preferred': self.get_global_preferred
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
    @controllers.handle_exceptions(u._('Certificate Authorities retrieval'))
    @controllers.enforce_rbac('certificate_authorities:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities on_get')

        plugin_name = kw.get('plugin_name')
        if plugin_name is not None:
            plugin_name = parse.unquote_plus(plugin_name)

        plugin_ca_id = kw.get('plugin_ca_id', None)
        if plugin_ca_id is not None:
            plugin_ca_id = parse.unquote_plus(plugin_ca_id)

        result = self.ca_repo.get_by_create_date(
            offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None),
            plugin_name=plugin_name,
            plugin_ca_id=plugin_ca_id,
            suppress_exception=True
        )

        cas, offset, limit, total = result

        if not cas:
            cas_resp_overall = {'cas': [],
                                'total': total}
        else:
            cas_resp = [
                hrefs.convert_certificate_authority_to_href(s.id)
                for s in cas
            ]
            cas_resp_overall = hrefs.add_nav_hrefs(
                'cas',
                offset,
                limit,
                total,
                {'cas': cas_resp}
            )
            cas_resp_overall.update({'total': total})

        return cas_resp_overall

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Retrieve global preferred CA'))
    @controllers.enforce_rbac('certificate_authorities:get_global_ca')
    def get_global_preferred(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities get_global_preferred CA')

        pref_ca = self.preferred_ca_repo.get_global_preferred_ca()
        if not pref_ca:
            pecan.abort(404, "No global preferred CA defined")

        return {
            'cas': [hrefs.convert_certificate_authority_to_href(pref_ca.ca_id)]
        }

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Retrieve project preferred CA'))
    @controllers.enforce_rbac('certificate_authorities:get_preferred_ca')
    def preferred(self, external_project_id, **kw):
        LOG.debug('Start certificate_authorities get project preferred CA')

        project = self.project_repo.find_by_external_project_id(
            external_project_id)

        pref_ca = self.preferred_ca_repo.get_project_entities(project.id)
        if not pref_ca:
            pecan.abort(404, "No preferred CA defined for this project")

        return {
            'cas':
            [hrefs.convert_certificate_authority_to_href(pref_ca[0].ca_id)]
        }
