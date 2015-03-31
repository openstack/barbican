# Copyright (c) 2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from six import moves

from barbican.common import hrefs
from barbican.common import resources as res
from barbican.model import models
from barbican.model import repositories
from barbican.tests import utils

project_repo = repositories.get_project_repository()
ca_repo = repositories.get_ca_repository()
project_ca_repo = repositories.get_project_repository()
preferred_ca_repo = repositories.get_preferred_ca_repository()


def create_ca(parsed_ca, id_ref="id"):
    """Generate a CA entity instance."""
    ca = models.CertificateAuthority(parsed_ca)
    ca.id = id_ref
    return ca


class WhenTestingCAsResource(utils.BarbicanAPIBaseTestCase):

    def test_should_get_list_certificate_authorities(self):
        self.create_cas()
        resp = self.app.get('/cas/', self.params)

        self.assertEqual(len(resp.namespace['cas']), self.limit)
        self.assertIn('previous', resp.namespace)
        self.assertIn('next', resp.namespace)

        url_nav_next = self._create_url(self.project_id,
                                        self.offset + self.limit, self.limit)
        self.assertEqual(resp.body.count(url_nav_next), 1)

        url_nav_prev = self._create_url(self.project_id,
                                        0, self.limit)
        self.assertEqual(resp.body.count(url_nav_prev), 1)

        url_hrefs = self._create_url(self.project_id)
        self.assertEqual(resp.body.count(url_hrefs), (self.limit + 2))

    def test_response_should_include_total(self):
        self.create_cas()
        resp = self.app.get('/cas/', self.params)
        self.assertIn('total', resp.namespace)
        self.assertEqual(self.num_cas, resp.namespace['total'])

    def test_should_get_list_certificate_authorities_with_params(self):
        self.create_cas()
        self.params['plugin_name'] = self.plugin_name
        self.params['plugin_ca_id'] = self.plugin_ca_id + str(1)
        self.params['offset'] = 0

        resp = self.app.get('/cas/', self.params)

        self.assertNotIn('previous', resp.namespace)
        self.assertNotIn('next', resp.namespace)
        self.assertEqual(resp.namespace['total'], 1)

    def test_should_handle_no_cas(self):
        self.params = {'offset': 0, 'limit': 2}
        resp = self.app.get('/cas/', self.params)
        self.assertEqual(resp.namespace.get('cas'), [])
        self.assertEqual(resp.namespace.get('total'), 0)
        self.assertNotIn('previous', resp.namespace)
        self.assertNotIn('next', resp.namespace)

    def test_should_get_global_preferred_ca(self):
        self.create_cas()

        resp = self.app.get('/cas/global-preferred')
        self.assertEqual(
            hrefs.convert_certificate_authority_to_href(self.global_ca_id),
            resp.namespace['cas'][0])

    def test_should_get_no_global_preferred_ca(self):
        resp = self.app.get('/cas/global-preferred', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_preferred_ca_not_found(self):
        self.project = res.get_or_create_project(self.project_id)
        project_repo.save(self.project)
        resp = self.app.get('/cas/preferred', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_preferred_ca(self):
        self.create_cas()
        resp = self.app.get('/cas/preferred')
        self.assertEqual(
            hrefs.convert_certificate_authority_to_href(
                self.preferred_project_ca_id),
            resp.namespace['cas'][0])

    def test_should_get_ca(self):
        self.create_cas()
        resp = self.app.get('/cas/{0}'.format(self.selected_ca_id))
        self.assertEqual(self.selected_ca_id,
                         resp.namespace['ca_id'])
        self.assertEqual(self.selected_plugin_ca_id,
                         resp.namespace['plugin_ca_id'])

    def test_should_throw_exception_for_get_when_ca_not_found(self):
        self.create_cas()
        resp = self.app.get('/cas/bogus_ca_id', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_signing_certificate(self):
        self.create_cas()
        resp = self.app.get('/cas/{0}/cacert'.format(self.selected_ca_id))
        self.assertEqual(self.selected_signing_cert, resp.body)

    def test_should_raise_for_get_signing_certificate_ca_not_found(self):
        resp = self.app.get('/cas/bogus_ca/cacert', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_cert_chain(self):
        self.create_cas()
        resp = self.app.get('/cas/{0}/intermediates'.format(
            self.selected_ca_id))

        self.assertEqual(self.selected_intermediates, resp.body)

    def test_should_raise_for_get_cert_chain_ca_not_found(self):
        resp = self.app.get('/cas/bogus_ca/intermediates', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_add_to_project(self):
        self.create_cas()
        resp = self.app.post('/cas/{0}/add-to-project'.format(
            self.selected_ca_id))
        self.assertEqual(204, resp.status_int)
        # TODO(alee) need more detailed tests here

    def test_should_add_existing_project_ca_to_project(self):
        self.create_cas()
        resp = self.app.post('/cas/{0}/add-to-project'.format(
            self.project_ca_ids[0]))
        self.assertEqual(204, resp.status_int)
        # TODO(alee) need more detailed tests here

    def test_should_raise_add_to_project_on_ca_not_found(self):
        resp = self.app.post(
            '/cas/bogus_ca/add-to-project', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_raise_add_to_project_not_post(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/add_to_project'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_remove_from_project(self):
        self.create_cas()
        resp = self.app.post('/cas/{0}/remove-from-project'.format(
            self.project_ca_ids[0]))
        self.assertEqual(204, resp.status_int)
        # TODO(alee) need more detailed tests here

    def test_should_remove_from_project_not_currently_set(self):
        self.create_cas()
        resp = self.app.post('/cas/{0}/remove-from-project'.format(
            self.selected_ca_id))
        self.assertEqual(204, resp.status_int)
        # TODO(alee) need more detailed tests here

    def test_should_raise_remove_form_project_on_ca_not_found(self):
        self.create_cas()
        resp = self.app.post('/cas/bogus_ca/remove-from-project',
                             expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_raise_remove_from_project_not_post(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/remove-from-project'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_set_preferred_modify_existing(self):
        self.create_cas()
        self.app.post(
            '/cas/{0}/set-preferred'.format(self.project_ca_ids[1]))

    def test_should_raise_set_preferred_ca_not_found(self):
        self.create_cas()
        resp = self.app.post('/cas/bogus_ca/set-preferred', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_raise_set_preferred_ca_not_in_project(self):
        self.create_cas()
        resp = self.app.post(
            '/cas/{0}/set-preferred'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_should_raise_set_preferred_ca_not_post(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/set-preferred'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_set_global_preferred(self):
        self.create_cas()
        self.app.post(
            '/cas/{0}/set-global-preferred'.format(self.selected_ca_id))

    def test_should_raise_set_global_preferred_ca_not_found(self):
        resp = self.app.post(
            '/cas/bogus_ca/set-global-preferred',
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_raise_set_global_preferred_ca_not_post(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/set-global-preferred'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_unset_global_preferred(self):
        self.create_cas()
        resp = self.app.post(
            '/cas/{0}/unset-global-preferred'.format(self.global_ca_id))
        self.assertEqual(204, resp.status_int)

    def test_should_unset_global_preferred_not_post(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/unset-global-preferred'.format(self.selected_ca_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_should_raise_unset_global_preferred_ca_not_found(self):
        resp = self.app.post(
            '/cas/bogus_ca/unset-global-preferred',
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_projects(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/{0}/projects'.format(self.project_ca_ids[0]))
        self.assertEqual(
            self.project.id,
            resp.namespace['projects'][0])

    def test_should_get_no_projects(self):
        self.create_cas()
        resp = self.app.get('/cas/{0}/projects'.format(self.selected_ca_id))
        self.assertEqual(resp.namespace['projects'], [])

    def test_should_raise_get_projects_ca_not_found(self):
        self.create_cas()
        resp = self.app.get(
            '/cas/bogus_ca/projects'.format(self.project_ca_ids[0]),
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def create_cas(self):
        self.project = res.get_or_create_project(self.project_id)
        project_repo.save(self.project)
        self.project_ca_ids = []

        self.plugin_name = 'default_plugin'
        self.plugin_ca_id = 'default_plugin_ca_id_'
        self.ca_id = "id1"

        self.num_cas = 10
        self.offset = 2
        self.limit = 4
        self.params = {'offset': self.offset, 'limit': self.limit}

        for ca_id in moves.range(self.num_cas):
            parsed_ca = {
                'plugin_name': self.plugin_name,
                'plugin_ca_id': self.plugin_ca_id + str(ca_id),
                'name': self.plugin_name,
                'description': 'Master CA for default plugin',
                'ca_signing_certificate': 'ZZZZZ' + str(ca_id),
                'intermediates': 'YYYYY' + str(ca_id)
            }
            ca = models.CertificateAuthority(parsed_ca)
            ca_repo.create_from(ca)
            ca_repo.save(ca)

            if ca_id == 1:
                # set global preferred ca
                pref_ca = models.PreferredCertificateAuthority(
                    preferred_ca_repo.PREFERRED_PROJECT_ID,
                    ca.id)
                preferred_ca_repo.create_from(pref_ca)
                preferred_ca_repo.save(pref_ca)
                self.global_ca_id = ca.id

            if ca_id == 2:
                # set project CA
                project_ca = models.ProjectCertificateAuthority(
                    self.project.id, ca.id)
                project_ca_repo.create_from(project_ca)
                project_ca_repo.save(project_ca)
                self.project_ca_ids.append(ca.id)

            if ca_id == 3:
                # set project preferred CA
                project_ca = models.ProjectCertificateAuthority(
                    self.project.id, ca.id)
                project_ca_repo.create_from(project_ca)
                project_ca_repo.save(project_ca)
                self.project_ca_ids.append(ca.id)

                pref_ca = models.PreferredCertificateAuthority(
                    self.project.id, ca.id)
                preferred_ca_repo.create_from(pref_ca)
                preferred_ca_repo.save(pref_ca)
                self.preferred_project_ca_id = ca.id

            if ca_id == 4:
                # set ca for testing GETs for a single CA
                self.selected_ca_id = ca.id
                self.selected_plugin_ca_id = self.plugin_ca_id + str(ca_id)
                self.selected_signing_cert = 'ZZZZZ' + str(ca_id)
                self.selected_intermediates = 'YYYYY' + str(ca_id)

    def _create_url(self, external_project_id, offset_arg=None,
                    limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/cas?limit={0}&offset={1}'.format(
                limit, offset)
        else:
            return '/cas'
