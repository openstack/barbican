# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

from barbican.common import exception
from barbican.common import resources as res
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingCertificateAuthorityRepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingCertificateAuthorityRepo, self).setUp()
        self.ca_repo = repositories.CertificateAuthorityRepo()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'name': 'Dogtag CA',
                          'expiration': expiration.isoformat(),
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}
        self.parsed_ca2 = {'plugin_name': 'symantec_plugin',
                           'plugin_ca_id': 'ca_master_2',
                           'name': 'Symantec CA2',
                           'expiration': expiration.isoformat(),
                           'description': 'Master CA for Dogtag plugin2',
                           'ca_signing_certificate': 'XXXXX',
                           'intermediates': 'YYYYY'}

    def _add_ca(self, parsed_ca, session):
        ca = self.ca_repo.create_from(models.CertificateAuthority(parsed_ca),
                                      session=session)
        return ca

    def test_get_by_create_date(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        session.commit()

        retrieved_cas, offset, limit, total = self.ca_repo.get_by_create_date(
            session=session
        )

        self.assertEqual([ca.id], [s.id for s in retrieved_cas])
        self.assertEqual([ca.plugin_name],
                         [s.plugin_name for s in retrieved_cas])
        self.assertEqual(
            [self.parsed_ca['ca_signing_certificate']],
            [s.ca_meta['ca_signing_certificate'].value for s in retrieved_cas])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_with_plugin_name_filter(self):
        session = self.ca_repo.get_session()
        ca1 = self._add_ca(self.parsed_ca, session)
        self._add_ca(self.parsed_ca2, session)

        retrieved_cas, offset, limit, total = self.ca_repo.get_by_create_date(
            session=session,
            plugin_name=self.parsed_ca['plugin_name']
        )

        self.assertEqual([ca1.id], [s.id for s in retrieved_cas])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_with_plugin_ca_id_filter(self):
        session = self.ca_repo.get_session()
        ca1 = self._add_ca(self.parsed_ca, session)
        self._add_ca(self.parsed_ca2, session)

        retrieved_cas, offset, limit, total = self.ca_repo.get_by_create_date(
            session=session,
            plugin_ca_id=self.parsed_ca['plugin_ca_id']
        )

        self.assertEqual([ca1.id], [s.id for s in retrieved_cas])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_nothing(self):
        session = self.ca_repo.get_session()
        retrieved_cas, offset, limit, total = self.ca_repo.get_by_create_date(
            session=session,
            suppress_exception=True
        )

        self.assertEqual([], retrieved_cas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_do_entity_name(self):
        self.assertEqual("CertificateAuthority",
                         self.ca_repo._do_entity_name())

    def test_should_raise_no_result_found(self):
        session = self.ca_repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.ca_repo.get_by_create_date,
            session=session,
            suppress_exception=False)

    def test_get_count_should_return_zero(self):
        session = self.ca_repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        session.commit()
        count = self.ca_repo.get_count(project.id, session=session)

        self.assertEqual(0, count)

    def test_get_count_should_return_one(self):
        session = self.ca_repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        ca_model = models.CertificateAuthority(self.parsed_ca)
        ca_model.project_id = project.id
        self.ca_repo.create_from(ca_model, session=session)

        session.commit()
        count = self.ca_repo.get_count(project.id, session=session)

        self.assertEqual(1, count)

    def test_get_count_should_return_one_after_delete(self):
        session = self.ca_repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        ca_model = models.CertificateAuthority(self.parsed_ca)
        ca_model.project_id = project.id
        self.ca_repo.create_from(ca_model, session=session)

        ca_model = models.CertificateAuthority(self.parsed_ca)
        ca_model.project_id = project.id
        self.ca_repo.create_from(ca_model, session=session)

        session.commit()
        count = self.ca_repo.get_count(project.id, session=session)
        self.assertEqual(2, count)

        self.ca_repo.delete_entity_by_id(ca_model.id, "my keystone id",
                                         session=session)
        session.commit()

        count = self.ca_repo.get_count(project.id, session=session)
        self.assertEqual(1, count)


class WhenTestingProjectCARepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingProjectCARepo, self).setUp()
        self.ca_repo = repositories.CertificateAuthorityRepo()
        self.project_ca_repo = repositories.ProjectCertificateAuthorityRepo()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'expiration': expiration.isoformat(),
                          'name': 'Dogtag CA',
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}
        self.parsed_ca2 = {'plugin_name': 'symantec_plugin',
                           'plugin_ca_id': 'ca_master_2',
                           'expiration': expiration.isoformat(),
                           'name': 'Symantec CA2',
                           'description': 'Master CA for Dogtag plugin2',
                           'ca_signing_certificate': 'XXXXX',
                           'intermediates': 'YYYYY'}

    def _add_ca(self, parsed_ca, session):
        ca = self.ca_repo.create_from(models.CertificateAuthority(parsed_ca),
                                      session=session)
        return ca

    def _add_project(self, project_id, session):
        project = models.Project()
        project.external_id = project_id
        project.save(session=session)
        return project

    def _add_project_ca(self, project_id, ca_id, session):
        project_ca = self.project_ca_repo.create_from(
            models.ProjectCertificateAuthority(project_id, ca_id),
            session)
        return project_ca

    def test_get_by_create_date(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        project = self._add_project("project_1", session)
        self._add_project_ca(project.id, ca.id, session)

        session.commit()

        retrieved_pcas, offset, limit, total = (
            self.project_ca_repo.get_by_create_date(session=session))

        self.assertEqual([ca.id], [s.ca_id for s in retrieved_pcas])
        self.assertEqual([project.id], [s.project_id for s in retrieved_pcas])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_project_entities(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        project = self._add_project("project_1", session)
        self._add_project_ca(project.id, ca.id, session)

        session.commit()

        retrieved_pcas = self.project_ca_repo.get_project_entities(
            project.id, session)
        self.assertEqual([ca.id], [s.ca_id for s in retrieved_pcas])

    def test_get_by_create_date_with_ca_id_filter(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        project = self._add_project("project_1", session)
        project_ca = self._add_project_ca(project.id, ca.id, session)

        ca2 = self._add_ca(self.parsed_ca2, session)
        project2 = self._add_project("project_2", session)
        self._add_project_ca(project2.id, ca2.id, session)

        session.commit()

        retrieved_pcas, offset, limit, total = (
            self.project_ca_repo.get_by_create_date(
                session=session,
                ca_id=ca.id))

        self.assertEqual([project_ca.id],
                         [s.id for s in retrieved_pcas])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_nothing(self):
        session = self.project_ca_repo.get_session()
        retrieved_pcas, offset, limit, total = (
            self.project_ca_repo.get_by_create_date(
                session=session,
                suppress_exception=True))

        self.assertEqual([], retrieved_pcas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_do_entity_name(self):
        self.assertEqual("ProjectCertificateAuthority",
                         self.project_ca_repo._do_entity_name())

    def test_should_raise_no_result_found(self):
        session = self.project_ca_repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.project_ca_repo.get_by_create_date,
            session=session,
            suppress_exception=False)


class WhenTestingPreferredCARepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingPreferredCARepo, self).setUp()
        self.ca_repo = repositories.CertificateAuthorityRepo()
        self.preferred_ca_repo = (
            repositories.PreferredCertificateAuthorityRepo())

        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))

        expiration_later = (datetime.datetime.utcnow() +
                            datetime.timedelta(days=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'expiration': expiration.isoformat(),
                          'name': 'Dogtag CA',
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}

        self.parsed_ca2 = {'plugin_name': 'symantec_plugin',
                           'plugin_ca_id': 'ca_master_2',
                           'expiration': expiration.isoformat(),
                           'name': 'Symantec CA2',
                           'description': 'Master CA for Dogtag plugin2',
                           'ca_signing_certificate': 'XXXXX',
                           'intermediates': 'YYYYY'}

        self.parsed_modified_ca = {
            'plugin_name': 'dogtag_plugin',
            'plugin_ca_id': 'ca_master',
            'expiration': expiration_later.isoformat(),
            'name': 'Dogtag CA',
            'description': 'Updated Master CA for Dogtag plugin',
            'ca_signing_certificate': 'XXXXX-updated-XXXXX',
            'intermediates': 'YYYYY'}

        self.global_project = res.get_or_create_global_preferred_project()

    def _add_ca(self, parsed_ca, session):
        ca = self.ca_repo.create_from(models.CertificateAuthority(parsed_ca),
                                      session=session)
        return ca

    def _add_project(self, project_id, session):
        project = models.Project()
        project.external_id = project_id
        project.save(session=session)
        return project

    def _add_preferred_ca(self, project_id, ca_id, session):
        preferred_ca = self.preferred_ca_repo.create_from(
            models.PreferredCertificateAuthority(project_id, ca_id),
            session)
        return preferred_ca

    def _add_global_preferred_ca(self, ca_id, session):
        preferred_ca = self.preferred_ca_repo.create_from(
            models.PreferredCertificateAuthority(
                self.global_project.id,
                ca_id),
            session)
        return preferred_ca

    def test_get_by_create_date(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        self._add_ca(self.parsed_ca2, session)
        project = self._add_project("project_1", session)
        self._add_preferred_ca(project.id, ca.id, session)

        session.commit()

        pca, offset, limit, total = self.preferred_ca_repo.get_by_create_date(
            session=session
        )

        self.assertEqual([ca.id], [s.ca_id for s in pca])
        self.assertEqual([project.id], [s.project_id for s in pca])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_with_params(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        self._add_ca(self.parsed_ca2, session)
        project = self._add_project("project_1", session)
        self._add_preferred_ca(project.id, ca.id, session)

        session.commit()

        pca, offset, limit, total = self.preferred_ca_repo.get_by_create_date(
            session=session,
            project_id=project.id,
            ca_id=ca.id
        )

        self.assertEqual([ca.id], [s.ca_id for s in pca])
        self.assertEqual([project.id], [s.project_id for s in pca])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_project_entities(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        self._add_ca(self.parsed_ca2, session)
        project = self._add_project("project_1", session)
        self._add_preferred_ca(project.id, ca.id, session)

        session.commit()
        pca = self.preferred_ca_repo.get_project_entities(project.id, session)
        self.assertEqual([ca.id], [s.ca_id for s in pca])

    def test_get_nothing(self):
        session = self.preferred_ca_repo.get_session()
        retrieved_pcas, offset, limit, total = (
            self.preferred_ca_repo.get_by_create_date(
                session=session,
                suppress_exception=True))

        self.assertEqual([], retrieved_pcas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_do_entity_name(self):
        self.assertEqual("PreferredCertificateAuthority",
                         self.preferred_ca_repo._do_entity_name())

    def test_should_raise_no_result_found(self):
        session = self.preferred_ca_repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.preferred_ca_repo.get_by_create_date,
            session=session,
            suppress_exception=False)

    def test_should_raise_constraint_check(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        ca2 = self._add_ca(self.parsed_ca2, session)
        project = self._add_project("project_1", session)
        self._add_preferred_ca(project.id, ca.id, session)
        self.assertRaises(
            exception.ConstraintCheck,
            self._add_preferred_ca,
            project.id,
            ca2.id,
            session)

    def test_set_global_preferred_ca(self):
        session = self.ca_repo.get_session()

        ca = self._add_ca(self.parsed_ca, session)
        self._add_global_preferred_ca(ca.id, session)
        session.commit()

        pca = self.preferred_ca_repo.get_project_entities(
            self.global_project.id,
            session)
        self.assertEqual([ca.id], [s.ca_id for s in pca])

    def test_should_create(self):
        session = self.ca_repo.get_session()
        ca = self._add_ca(self.parsed_ca, session)
        project = self._add_project("project_1", session)

        self.preferred_ca_repo.create_or_update_by_project_id(
            project.id, ca.id)
        session.commit()

    def test_should_update(self):
        session = self.ca_repo.get_session()
        ca1 = self._add_ca(self.parsed_ca, session)
        ca2 = self._add_ca(self.parsed_ca2, session)
        project = self._add_project("project_1", session)

        self.preferred_ca_repo.create_or_update_by_project_id(
            project.id, ca1.id)
        session.commit()
        self.preferred_ca_repo.create_or_update_by_project_id(
            project.id, ca2.id)
        session.commit()
