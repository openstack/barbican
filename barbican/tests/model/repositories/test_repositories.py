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

from unittest import mock

from alembic import script as alembic_script
from oslo_config import cfg
import sqlalchemy

from barbican.common import config
from barbican.common import exception
from barbican.model.migration import commands as migration
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils
from barbican.tests import utils


class WhenCleaningRepositoryPagingParameters(utils.BaseTestCase):

    def setUp(self):
        super(WhenCleaningRepositoryPagingParameters, self).setUp()
        self.CONF = config.CONF
        self.default_limit = self.CONF.default_limit_paging

    def test_parameters_not_assigned(self):
        """The cleaner should use defaults when params are not specified."""
        clean_offset, clean_limit = repositories.clean_paging_values()

        self.assertEqual(0, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)

    def test_limit_as_none(self):
        """When Limit is set to None it should use the default limit."""
        offset = 0
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=offset,
            limit_arg=None)

        self.assertEqual(offset, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)

    def test_offset_as_none(self):
        """When Offset is set to None it should use an offset of 0."""
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=None,
            limit_arg=self.default_limit)

        self.assertEqual(0, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)

    def test_limit_as_uncastable_str(self):
        """When Limit cannot be cast to an int, expect the default."""
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=0,
            limit_arg='boom')
        self.assertEqual(0, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)

    def test_offset_as_uncastable_str(self):
        """When Offset cannot be cast to an int, it should be zero."""
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg='boom',
            limit_arg=self.default_limit)
        self.assertEqual(0, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)

    def test_limit_is_less_than_one(self):
        """Offset should default to 1."""
        limit = -1
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=1,
            limit_arg=limit)
        self.assertEqual(1, clean_offset)
        self.assertEqual(1, clean_limit)

    def test_limit_is_too_big(self):
        """Limit should max out at configured value."""
        limit = self.CONF.max_limit_paging + 10
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=1,
            limit_arg=limit)
        self.assertEqual(self.CONF.max_limit_paging, clean_limit)

    def test_offset_is_too_big(self):
        """When Offset exceeds sys.maxsize, it should be zero."""
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=265613988875874769338781322035779626829233452653394495,
            limit_arg=self.default_limit)
        self.assertEqual(0, clean_offset)
        self.assertEqual(self.default_limit, clean_limit)


class WhenInvokingExceptionMethods(utils.BaseTestCase):

    def setUp(self):
        super(WhenInvokingExceptionMethods, self).setUp()
        self.CONF = config.CONF

        self.entity_id = '123456'
        self.entity_name = 'test_entity'

    def test_should_raise_for_entity_not_found(self):

        exception_result = self.assertRaises(
            exception.NotFound,
            repositories._raise_entity_not_found,
            self.entity_name,
            self.entity_id)

        self.assertEqual(
            "No test_entity found with ID 123456",
            str(exception_result))

    def test_should_raise_for_entity_id_not_found(self):

        exception_result = self.assertRaises(
            exception.NotFound,
            repositories._raise_entity_id_not_found,
            self.entity_id)

        self.assertEqual(
            "Entity ID 123456 not found",
            str(exception_result))

    def test_should_raise_for_no_entities_found(self):

        exception_result = self.assertRaises(
            exception.NotFound,
            repositories._raise_no_entities_found,
            self.entity_name)

        self.assertEqual(
            "No entities of type test_entity found",
            str(exception_result))


class WhenTestingBaseRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingBaseRepository, self).setUp()
        self.repo = repositories.BaseRepo()

    def test_should_raise_invalid_create_from_no_entity(self):
        exception_result = self.assertRaises(
            exception.Invalid,
            self.repo.create_from,
            None)

        self.assertEqual(
            "Must supply non-None Entity.",
            str(exception_result))

    def test_should_raise_invalid_create_from_entity_with_id(self):
        entity = models.ModelBase()
        entity.id = '1234'

        exception_result = self.assertRaises(
            exception.Invalid,
            self.repo.create_from,
            entity)

        self.assertEqual(
            "Must supply Entity with id=None (i.e. new entity).",
            str(exception_result))

    def test_should_raise_invalid_do_validate_no_status(self):
        exception_result = self.assertRaises(
            exception.Invalid,
            self.repo._do_validate,
            {})

        self.assertEqual(
            "Entity status is required.",
            str(exception_result))

    def test_should_raise_invalid_do_validate_bad_status(self):
        exception_result = self.assertRaises(
            exception.Invalid,
            self.repo._do_validate,
            dict(status='BOGUS_STATUS'))

        self.assertEqual(
            "Invalid status 'BOGUS_STATUS' for Entity.",
            str(exception_result))


class WhenTestingWrapDbError(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingWrapDbError, self).setUp()
        repositories.CONF.set_override("sql_max_retries", 0)
        repositories.CONF.set_override("sql_retry_interval", 0)

    @mock.patch('barbican.model.repositories.is_db_connection_error')
    def test_should_raise_operational_error_is_connection_error(
            self, mock_is_db_error):
        mock_is_db_error.return_value = True

        @repositories.wrap_db_error
        def test_function():
            raise sqlalchemy.exc.OperationalError(
                'statement', 'params', 'orig')

        self.assertRaises(
            sqlalchemy.exc.OperationalError,
            test_function)


class WhenTestingGetEnginePrivate(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingGetEnginePrivate, self).setUp()

        repositories.CONF.set_override("sql_connection", "connection")

    @mock.patch('barbican.model.repositories._create_engine')
    def test_should_raise_value_exception_engine_create_failure(
            self, mock_create_engine):
        engine = mock.MagicMock()
        engine.connect.side_effect = ValueError('Abort!')
        mock_create_engine.return_value = engine

        exception_result = self.assertRaises(
            exception.BarbicanException,
            repositories._get_engine,
            None)

        self.assertEqual(
            'Error configuring registry database with supplied '
            'sql_connection. Got error: Abort!',
            str(exception_result))

    @mock.patch('barbican.model.repositories._create_engine')
    def test_should_complete_with_no_alembic_create_default_configs(
            self, mock_create_engine):

        repositories.CONF.set_override("db_auto_create", False)
        engine = mock.MagicMock()
        mock_create_engine.return_value = engine

        # Invoke method under test.
        repositories._get_engine(None)

        engine.connect.assert_called_once_with()
        mock_create_engine.assert_called_once_with(
            'connection',
            connection_recycle_time=3600,
            max_pool_size=repositories.CONF.sql_pool_size,
            max_overflow=repositories.CONF.sql_pool_max_overflow
        )

    @mock.patch('barbican.model.repositories._create_engine')
    def test_should_complete_with_no_alembic_create_pool_configs(
            self, mock_create_engine):

        repositories.CONF.set_override("db_auto_create", False)
        repositories.CONF.set_override(
            "sql_pool_class", "QueuePool")
        repositories.CONF.set_override("sql_pool_size", 22)
        repositories.CONF.set_override("sql_pool_max_overflow", 11)

        engine = mock.MagicMock()
        mock_create_engine.return_value = engine

        # Invoke method under test.
        repositories._get_engine(None)

        engine.connect.assert_called_once_with()
        mock_create_engine.assert_called_once_with(
            'connection',
            connection_recycle_time=3600,
            max_pool_size=22,
            max_overflow=11
        )


class WhenTestingAutoGenerateTables(utils.BaseTestCase):

    @mock.patch('barbican.model.migration.commands.upgrade')
    def test_should_complete_with_alembic_database_update(
            self, mock_commands_upgrade):

        tables = dict(
            alembic_version='version')  # Mimic tables already created.
        engine = 'engine'

        # Invoke method under test.
        repositories._auto_generate_tables(engine, tables)

        mock_commands_upgrade.assert_called_once_with()


class WhenTestingIsDbConnectionError(utils.BaseTestCase):

    def test_should_return_false_no_error_code_in_args(self):

        args = mock.MagicMock()
        args.find.return_value = -1

        result = repositories.is_db_connection_error(args)

        self.assertFalse(result)

    def test_should_return_true_error_code_found_in_args(self):

        args = mock.MagicMock()
        args.find.return_value = 1

        result = repositories.is_db_connection_error(args)

        self.assertTrue(result)


class WhenTestingMigrations(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingMigrations, self).setUp()
        repositories.CONF.set_override("sql_connection", "connection")
        self.alembic_config = migration.init_config()
        self.alembic_config.barbican_config = cfg.CONF

    def test_no_downgrade(self):
        script_dir = alembic_script.ScriptDirectory.from_config(
            self.alembic_config)
        versions = [v for v in script_dir.walk_revisions(base='base',
                                                         head='heads')]
        failed_revisions = []
        for version in versions:
            if hasattr(version.module, 'downgrade'):
                failed_revisions.append(version.revision)

        if failed_revisions:
            self.fail('Migrations %s have downgrade' % failed_revisions)


class DummyRepo(repositories.BaseRepo):
    """Repository for the increasing code coverage of unit tests."""
    def get_session(self, session=None):
        return None

    def _do_entity_name(self):
        return "Dummy"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        return None

    def _do_validate(self, values):
        pass

    def _build_get_project_entities_query(self, project_id, session):
        return None


class WhenIncreasingRepositoryTestCoverage(utils.BaseTestCase):

    def test_get_count_should_return_zero(self):
        dummy_repo = DummyRepo()
        count = dummy_repo.get_count('dummy_project_id')
        self.assertEqual(0, count)

    def test_get_project_entities_should_return_empty(self):
        dummy_repo = DummyRepo()
        count = dummy_repo.get_project_entities('dummy_project_id')
        self.assertEqual([], count)
