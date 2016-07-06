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

import fixtures
import testtools

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.interface import secret_store as ss
from barbican.tests import database_utils
from barbican.tests import fixture
from barbican.tests import utils


@utils.parameterized_test_case
class WhenTestingSecretRepository(database_utils.RepositoryTestCase):

    dataset_for_filter_tests = {
        'query_by_name': {
            'secret_1_dict': dict(name="name1"),
            'secret_2_dict': dict(name="name2"),
            'query_dict': dict(name="name1")
        },
        'query_by_algorithm': {
            'secret_1_dict': dict(algorithm="algorithm1"),
            'secret_2_dict': dict(algorithm="algorithm2"),
            'query_dict': dict(alg="algorithm1")
        },
        'query_by_mode': {
            'secret_1_dict': dict(mode="mode1"),
            'secret_2_dict': dict(mode="mode2"),
            'query_dict': dict(mode="mode1")
        },
        'query_by_bit_length': {
            'secret_1_dict': dict(bit_length=1024),
            'secret_2_dict': dict(bit_length=2048),
            'query_dict': dict(bits=1024)
        },
        'query_by_secret_type': {
            'secret_1_dict': dict(secret_type=ss.SecretType.SYMMETRIC),
            'secret_2_dict': dict(secret_type=ss.SecretType.OPAQUE),
            'query_dict': dict(secret_type=ss.SecretType.SYMMETRIC)
        },
    }

    def setUp(self):
        super(WhenTestingSecretRepository, self).setUp()
        self.repo = repositories.SecretRepo()

    def test_get_secret_list(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret = self.repo.create_from(secret_model, session=session)

        session.commit()

        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            session=session,
        )

        self.assertEqual([secret.id], [s.id for s in secrets])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_secret_by_id(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret = self.repo.create_from(secret_model, session=session)

        session.commit()

        db_secret = self.repo.get_secret_by_id(secret.id)
        self.assertIsNotNone(db_secret)

    def test_should_raise_notfound_exception(self):
        self.assertRaises(exception.NotFound, self.repo.get_secret_by_id,
                          "invalid_id", suppress_exception=False)

    def test_should_suppress_notfound_exception(self):
        self.assertIsNone(self.repo.get_secret_by_id("invalid_id",
                                                     suppress_exception=True))

    @utils.parameterized_dataset(dataset_for_filter_tests)
    def test_get_secret_list_with_filter(self, secret_1_dict, secret_2_dict,
                                         query_dict):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_1_dict['project_id'] = project.id
        secret1 = self.repo.create_from(
            models.Secret(secret_1_dict),
            session=session,
        )
        secret_2_dict['project_id'] = project.id
        secret2 = self.repo.create_from(
            models.Secret(secret_2_dict),
            session=session,
        )

        session.commit()

        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            session=session,
            **query_dict
        )
        resulting_secret_ids = [s.id for s in secrets]
        self.assertIn(secret1.id, resulting_secret_ids)
        self.assertNotIn(secret2.id, resulting_secret_ids)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_nothing(self):
        session = self.repo.get_session()
        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            bits=1024,
            session=session,
            suppress_exception=True
        )

        self.assertEqual([], secrets)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_do_entity_name(self):
        self.assertEqual("Secret", self.repo._do_entity_name())

    def test_should_raise_no_result_found(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_secret_list,
            "my keystone id",
            session=session,
            suppress_exception=False)

    def test_should_get_count_zero(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)

        self.assertEqual(0, count)

    def test_should_get_count_one(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)

        self.assertEqual(1, count)

    def test_should_get_count_one_after_delete(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(2, count)

        self.repo.delete_entity_by_id(secret_model.id, "my keystone id",
                                      session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)

    def test_should_get_count_one_after_expiration(self):
        current_time = datetime.datetime.utcnow()
        tomorrow = current_time + datetime.timedelta(days=1)
        yesterday = current_time - datetime.timedelta(days=1)

        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret_model.expiration = tomorrow
        self.repo.create_from(secret_model, session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret_model.expiration = yesterday
        self.repo.create_from(secret_model, session=session)

        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)


class WhenTestingQueryFilters(testtools.TestCase,
                              fixtures.TestWithFixtures):

    def setUp(self):
        super(WhenTestingQueryFilters, self).setUp()
        self._session_fixture = self.useFixture(fixture.SessionQueryFixture())
        self.session = self._session_fixture.Session()
        self.query = self.session.query(models.Secret)
        self.repo = repositories.SecretRepo()

    def test_data_includes_six_secrets(self):
        self.assertEqual(6, len(self.query.all()))

    def test_sort_by_name_defaults_ascending(self):
        query = self.repo._build_sort_filter_query(self.query, 'name')
        secrets = query.all()
        self.assertEqual('A', secrets[0].name)

    def test_sort_by_name_desc(self):
        query = self.repo._build_sort_filter_query(self.query, 'name:desc')
        secrets = query.all()
        self.assertEqual('F', secrets[0].name)

    def test_sort_by_created_asc(self):
        query = self.repo._build_sort_filter_query(self.query, 'created:asc')
        secrets = query.all()
        self.assertEqual('A', secrets[0].name)

    def test_sort_by_updated_desc(self):
        query = self.repo._build_sort_filter_query(self.query, 'updated:desc')
        secrets = query.all()
        self.assertEqual('F', secrets[0].name)

    def test_filter_by_created_on_new_years(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            '2016-01-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(1, len(secrets))
        self.assertEqual('A', secrets[0].name)

    def test_filter_by_created_after_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gt:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(3, len(secrets))

    def test_filter_by_created_on_or_after_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gte:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(4, len(secrets))

    def test_filter_by_created_before_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'lt:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(2, len(secrets))

    def test_filter_by_created_on_or_before_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'lte:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(3, len(secrets))

    def test_filter_by_created_between_march_and_may_inclusive(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gte:2016-03-01T00:00:00,lte:2016-05-01T00:00:00'
        )
        secrets = query.all()
        secret_names = [s.name for s in secrets]

        self.assertEqual(3, len(secrets))
        self.assertIn('C', secret_names)
        self.assertIn('D', secret_names)
        self.assertIn('E', secret_names)
