# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

from unittest import mock

from oslo_utils import uuidutils
import sqlalchemy

from barbican.common import exception
from barbican.common import resources as c_resources
from barbican.model import models
from barbican.model import repositories as rep
from barbican.plugin.crypto import manager
from barbican.plugin import resources as plugin
from barbican.tasks import keystone_consumer as consumer
from barbican.tests import database_utils


class InitializeDatabaseMixin(object):

    def _init_memory_db_setup(self):

        # Force a refresh of the singleton plugin manager for each test.
        manager._PLUGIN_MANAGER = None
        manager.CONF.set_override('enabled_crypto_plugins',
                                  ['simple_crypto'],
                                  group='crypto')

        self.project_id1 = uuidutils.generate_uuid()
        self.project_id2 = uuidutils.generate_uuid(dashed=False)

        self.project1_data = c_resources.get_or_create_project(
            self.project_id1)
        self.assertIsNotNone(self.project1_data)

        self.project2_data = c_resources.get_or_create_project(
            self.project_id2)
        self.assertIsNotNone(self.project2_data)

    def _create_secret_for_project(self, project_data):

        secret_info = {"name": uuidutils.generate_uuid(dashed=False),
                       "algorithm": "aes", "bit_length": 256, "mode": "cbc",
                       "payload_content_type": "application/octet-stream"}
        new_secret = plugin.generate_secret(
            secret_info, secret_info.get('payload_content_type'), project_data)

        return new_secret


class WhenUsingKeystoneEventConsumer(
        database_utils.RepositoryTestCase,
        InitializeDatabaseMixin):
    """Test all but the process() method on KeystoneEventConsumer class.

    For unit testing the process() method, use the
    WhenUsingKeystoneEventConsumerProcessMethod class.
    """

    def setUp(self):
        super(WhenUsingKeystoneEventConsumer, self).setUp()
        self.kek_repo = rep.get_kek_datum_repository()
        self.project_repo = rep.get_project_repository()
        self.secret_meta_repo = rep.get_secret_meta_repository()
        self.secret_repo = rep.get_secret_repository()
        self.transport_key_repo = rep.get_transport_key_repository()

    def test_get_project_entities_lookup_call(self):
        self._init_memory_db_setup()
        secret = self._create_secret_for_project(self.project2_data)

        project2_id = self.project2_data.id
        self.assertIsNotNone(secret)

        db_secrets = self.secret_repo.get_project_entities(project2_id)

        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        db_kek = self.kek_repo.get_project_entities(project2_id)
        self.assertEqual(1, len(db_kek))

        # secret_meta_repo does not implement function
        # _build_get_project_entities_query, so it should raise error
        self.assertRaises(NotImplementedError,
                          self.secret_meta_repo.get_project_entities,
                          project2_id)

        # transport_key_repo does not implement function
        # _build_get_project_entities_query, so it should raise error
        self.assertRaises(NotImplementedError,
                          self.transport_key_repo.get_project_entities,
                          project2_id)

    @mock.patch.object(models.Project, 'delete',
                       side_effect=sqlalchemy.exc.SQLAlchemyError)
    def test_delete_project_entities_alchemy_error_suppress_exception_true(
            self, mock_entity_delete):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # sqlalchemy error is suppressed here
        no_error = self.project_repo.delete_project_entities(
            project1_id, suppress_exception=True)
        self.assertIsNone(no_error)

    @mock.patch.object(models.Project, 'delete',
                       side_effect=sqlalchemy.exc.SQLAlchemyError)
    def test_delete_project_entities_alchemy_error_suppress_exception_false(
            self, mock_entity_delete):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # sqlalchemy error is not suppressed here
        self.assertRaises(exception.BarbicanException,
                          self.project_repo.delete_project_entities,
                          project1_id, suppress_exception=False)

    def test_delete_project_entities_not_impl_error_suppress_exception_true(
            self):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # NotImplementedError is not suppressed regardless of related flag
        self.assertRaises(NotImplementedError,
                          self.secret_meta_repo.delete_project_entities,
                          project1_id, suppress_exception=True)

    def test_delete_project_entities_not_impl_error_suppress_exception_false(
            self):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # NotImplementedError is not suppressed regardless of related flag
        self.assertRaises(NotImplementedError,
                          self.secret_meta_repo.delete_project_entities,
                          project1_id, suppress_exception=False)

    def test_invoke_handle_error(self):
        task = consumer.KeystoneEventConsumer()

        project = mock.MagicMock()
        project.project_id = 'project_id'
        status = 'status'
        message = 'message'
        exception_test = ValueError('Abort!')
        resource_type = 'type'
        operation_type = 'operation'

        task.handle_error(
            project, status, message, exception_test, project_id=None,
            resource_type=resource_type, operation_type=operation_type)


class WhenUsingKeystoneEventConsumerProcessMethod(
        database_utils.RepositoryTestCase,
        InitializeDatabaseMixin):
    """Test only the process() method on KeystoneEventConsumer class.

    For unit testing all but the process() method, use the
    WhenUsingKeystoneEventConsumer class.
    """

    def setUp(self):
        super(WhenUsingKeystoneEventConsumerProcessMethod, self).setUp()

        # Override the database start function as repositories.start() is
        # already invoked by the RepositoryTestCase base class setUp().
        # Similarly, override the clear function.
        self.task = consumer.KeystoneEventConsumer(
            db_start=mock.MagicMock(),
            db_clear=mock.MagicMock()
        )

    def test_project_entities_cleanup_for_no_matching_barbican_project(self):
        self._init_memory_db_setup()

        result = self.task.process(project_id=self.project_id1,
                                   resource_type='project',
                                   operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

    def test_project_entities_cleanup_for_missing_barbican_project(self):
        self._init_memory_db_setup()

        result = self.task.process(project_id=None,
                                   resource_type='project',
                                   operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

    @mock.patch.object(consumer.KeystoneEventConsumer, 'handle_success')
    def test_existing_project_entities_cleanup_for_plain_secret(
            self, mock_handle_success):
        self._init_memory_db_setup()
        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        secret_id = secret.id

        project1_id = self.project1_data.id

        secret_repo = rep.get_secret_repository()
        db_secrets = secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        # Get secret_store_metadata for related secret
        self.assertGreater(len(db_secrets[0].secret_store_metadata), 0)

        secret_metadata_id = list(db_secrets[0].
                                  secret_store_metadata.values())[0].id
        self.assertIsNotNone(secret_metadata_id)

        # Get db entry for secret_store_metadata by id to make sure its
        # presence before removing via delete project task
        secret_meta_repo = rep.get_secret_meta_repository()
        db_secret_store_meta = secret_meta_repo.get(
            entity_id=secret_metadata_id)
        self.assertIsNotNone(db_secret_store_meta)

        kek_repo = rep.get_kek_datum_repository()
        db_kek = kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))

        # task = consumer.KeystoneEventConsumer()
        result = self.task.process(project_id=self.project_id1,
                                   resource_type='project',
                                   operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

        mock_handle_success.assert_has_calls([])
        _, kwargs = mock_handle_success.call_args
        self.assertEqual(self.project_id1, kwargs['project_id'])
        self.assertEqual('project', kwargs['resource_type'])
        self.assertEqual('deleted', kwargs['operation_type'])

        # After project entities delete, make sure secret is not found
        ex = self.assertRaises(exception.NotFound, secret_repo.get,
                               entity_id=secret_id,
                               external_project_id=self.project_id1)
        self.assertIn(secret_id, str(ex))

        # After project entities delete, make sure kek data is not found
        entities = kek_repo.get_project_entities(project1_id)
        self.assertEqual(0, len(entities))

        project_repo = rep.get_project_repository()
        db_project = project_repo.get_project_entities(project1_id)
        self.assertEqual(0, len(db_project))

        # Should have deleted SecretStoreMetadatum via children delete
        self.assertRaises(exception.NotFound,
                          secret_meta_repo.get,
                          entity_id=secret_metadata_id)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'handle_error')
    @mock.patch.object(rep.ProjectRepo, 'delete_project_entities',
                       side_effect=exception.BarbicanException)
    def test_rollback_with_error_during_project_cleanup(self, mock_delete,
                                                        mock_handle_error):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        secret_id = secret.id
        project1_id = self.project1_data.id

        secret_repo = rep.get_secret_repository()
        db_secrets = secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        kek_repo = rep.get_kek_datum_repository()
        db_kek = kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))
        # Commit changes made so far before creating rollback scenario
        rep.commit()

        handle_error_mock = mock.MagicMock()
        self.task.handler_error = handle_error_mock

        self.assertRaises(exception.BarbicanException,
                          self.task.process, project_id=self.project_id1,
                          resource_type='project', operation_type='deleted')

        mock_handle_error.assert_called_once_with(
            self.project1_data,
            500,
            mock.ANY,
            mock.ANY,
            operation_type='deleted',
            project_id=mock.ANY,
            resource_type='project',
        )

        args, kwargs = mock_handle_error.call_args
        self.assertEqual(500, args[1])
        self.assertEqual(self.project_id1, kwargs['project_id'])
        self.assertEqual('project', kwargs['resource_type'])
        self.assertEqual('deleted', kwargs['operation_type'])
        # Make sure entities are still present after rollback
        db_secrets = secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret_id, db_secrets[0].id)

        db_kek = kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))

        project_repo = rep.get_project_repository()
        db_project = project_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_project))
