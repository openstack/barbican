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
import uuid

import mock
from oslo.config import cfg
import sqlalchemy

from barbican.common import exception
from barbican.common import resources as c_resources
from barbican.model import models
from barbican.model import repositories as rep
from barbican.plugin import resources as plugin
from barbican.tasks import keystone_consumer as consumer
from barbican.tests.queue import test_keystone_listener as listener_test
from barbican.tests import utils


class WhenUsingKeystoneEventConsumer(listener_test.UtilMixin,
                                     utils.BaseTestCase):

    IN_MEM_DB_CONN_STRING = 'sqlite://'

    def setUp(self):
        super(WhenUsingKeystoneEventConsumer, self).setUp()

        self.conf = cfg.CONF
        self.engine = None
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self.engine:
            self.engine.dispose()

    def _init_memory_db_setup(self):
        # using in-memory sqlalchemy database, sqlite, instead of simulating
        # data via mocks to verify transaction behavior (like rollback when
        # error occurs in middle of delete project entities logic). This also
        # helps in verifying that project_entities related query is defined
        # correctly.
        self.opt_in_group(None, sql_connection=self.IN_MEM_DB_CONN_STRING)

        self.project_id1 = uuid.uuid4().hex
        self.project_id2 = uuid.uuid4().hex

        rep._MAKER = None
        rep._ENGINE = None

        rep.configure_db()
        self.repos = rep.Repositories(
            project_repo=None, project_secret_repo=None, secret_repo=None,
            datum_repo=None, kek_repo=None, secret_meta_repo=None,
            order_repo=None, order_plugin_meta_repo=None,
            transport_key_repo=None, container_repo=None,
            container_secret_repo=None)

        self.project1_data = c_resources.get_or_create_project(
            self.project_id1, self.repos.project_repo)
        self.assertIsNotNone(self.project1_data)

        self.engine = rep.get_engine()

        self.project2_data = c_resources.get_or_create_project(
            self.project_id2, self.repos.project_repo)
        self.assertIsNotNone(self.project2_data)

    def _create_secret_for_project(self, project_data):

        secret_info = {"name": uuid.uuid4().hex, "algorithm": "aes",
                       "bit_length": 256, "mode": "cbc",
                       "payload_content_type": "application/octet-stream"}
        new_secret = plugin.generate_secret(
            secret_info, secret_info.get('payload_content_type'), project_data,
            self.repos)

        return new_secret

    def test_get_project_entities_lookup_call(self):
        self._init_memory_db_setup()
        secret = self._create_secret_for_project(self.project2_data)

        project2_id = self.project2_data.id
        self.assertIsNotNone(secret)

        db_secrets = self.repos.secret_repo.get_project_entities(project2_id)

        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        db_project_secret = (
            self.repos.project_secret_repo.get_project_entities(project2_id))
        self.assertEqual(1, len(db_project_secret))

        db_kek = self.repos.kek_repo.get_project_entities(project2_id)
        self.assertEqual(1, len(db_kek))

        # secret_meta_repo does not implement function
        # _build_get_project_entities_query, so it should raise error
        self.assertRaises(NotImplementedError,
                          self.repos.secret_meta_repo.get_project_entities,
                          project2_id)

        # transport_key_repo does not implement function
        # _build_get_project_entities_query, so it should raise error
        self.assertRaises(NotImplementedError,
                          self.repos.transport_key_repo.get_project_entities,
                          project2_id)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'handle_success')
    def test_existing_project_entities_cleanup_for_plain_secret(
            self, mock_handle_success):
        self._init_memory_db_setup()
        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        secret_id = secret.id

        project1_id = self.project1_data.id

        db_secrets = self.repos.secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        # Get secret_store_metadata for related secret
        self.assertTrue(len(db_secrets[0].secret_store_metadata) > 0)

        secret_metadata_id = db_secrets[0].secret_store_metadata.values()[0].id
        self.assertIsNotNone(secret_metadata_id)

        # Get db entry for secret_store_metadata by id to make sure its
        # presence before removing via delete project task
        db_secret_store_meta = self.repos.secret_meta_repo.get(
            entity_id=secret_metadata_id)
        self.assertIsNotNone(db_secret_store_meta)

        db_project_secret = (
            self.repos.project_secret_repo.get_project_entities(project1_id))
        self.assertEqual(1, len(db_project_secret))

        db_kek = self.repos.kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))

        task = consumer.KeystoneEventConsumer()
        result = task.process(project_id=self.project_id1,
                              resource_type='project',
                              operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

        mock_handle_success.assert_called()
        _, kwargs = mock_handle_success.call_args
        self.assertEqual(self.project_id1, kwargs['project_id'])
        self.assertEqual('project', kwargs['resource_type'])
        self.assertEqual('deleted', kwargs['operation_type'])

        # After project entities delete, make sure secret is not found
        ex = self.assertRaises(exception.NotFound, self.repos.secret_repo.get,
                               entity_id=secret_id,
                               keystone_id=self.project_id1)
        self.assertIn(secret_id, str(ex))

        # After project entities delete, make sure project_secret is not found
        entities = self.repos.project_secret_repo.get_project_entities(
            project1_id)
        self.assertEqual(0, len(entities))

        # After project entities delete, make sure kek data is not found
        entities = self.repos.kek_repo.get_project_entities(project1_id)
        self.assertEqual(0, len(entities))

        db_project = self.repos.project_repo.get_project_entities(project1_id)
        self.assertEqual(0, len(db_project))

        # Should have deleted SecretStoreMetadatum via children delete
        ex = self.assertRaises(exception.NotFound,
                               self.repos.secret_meta_repo.get,
                               entity_id=secret_metadata_id)

    def test_project_entities_cleanup_for_no_matching_barbican_project(self):
        self._init_memory_db_setup()

        task = consumer.KeystoneEventConsumer()
        result = task.process(project_id=self.project_id1,
                              resource_type='project',
                              operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

    def test_project_entities_cleanup_for_missing_barbican_project(self):
        self._init_memory_db_setup()

        task = consumer.KeystoneEventConsumer()
        result = task.process(project_id=None,
                              resource_type='project',
                              operation_type='deleted')
        self.assertIsNone(result, 'No return is expected as result')

    @mock.patch.object(models.Tenant, 'delete',
                       side_effect=sqlalchemy.exc.SQLAlchemyError)
    def test_delete_project_entities_alchemy_error_suppress_exception_true(
            self, mock_entity_delete):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # sqlalchemy error is suppressed here
        no_error = self.repos.project_repo.delete_project_entities(
            project1_id, suppress_exception=True)
        self.assertIsNone(no_error)

    @mock.patch.object(models.Tenant, 'delete',
                       side_effect=sqlalchemy.exc.SQLAlchemyError)
    def test_delete_project_entities_alchemy_error_suppress_exception_false(
            self, mock_entity_delete):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # sqlalchemy error is not suppressed here
        self.assertRaises(exception.BarbicanException,
                          self.repos.project_repo.delete_project_entities,
                          project1_id, suppress_exception=False)

    def test_delete_project_entities_not_impl_error_suppress_exception_true(
            self):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # NotImplementedError is not suppressed regardless of related flag
        self.assertRaises(NotImplementedError,
                          self.repos.secret_meta_repo.delete_project_entities,
                          project1_id, suppress_exception=True)

    def test_delete_project_entities_not_impl_error_suppress_exception_false(
            self):
        self._init_memory_db_setup()

        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        project1_id = self.project1_data.id
        # NotImplementedError is not suppressed regardless of related flag
        self.assertRaises(NotImplementedError,
                          self.repos.secret_meta_repo.delete_project_entities,
                          project1_id, suppress_exception=False)

    @mock.patch.object(consumer.KeystoneEventConsumer, 'handle_error')
    @mock.patch.object(rep.ProjectRepo, 'delete_project_entities',
                       side_effect=exception.BarbicanException)
    def test_rollback_with_error_during_project_cleanup(self, mock_delete,
                                                        mock_handle_error):
        self._init_memory_db_setup()

        rep.start()
        secret = self._create_secret_for_project(self.project1_data)
        self.assertIsNotNone(secret)

        secret_id = secret.id
        project1_id = self.project1_data.id

        db_secrets = self.repos.secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret.id, db_secrets[0].id)

        db_project_secret = (
            self.repos.project_secret_repo.get_project_entities(project1_id))
        self.assertEqual(1, len(db_project_secret))

        db_kek = self.repos.kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))
        # rollback changes made so far before creating rollback scenario
        rep.commit()

        task = consumer.KeystoneEventConsumer()
        handle_error_mock = mock.MagicMock()
        task.handler_error = handle_error_mock

        self.assertRaises(exception.BarbicanException,
                          task.process, project_id=self.project_id1,
                          resource_type='project', operation_type='deleted')

        mock_handle_error.assert_called()
        args, kwargs = mock_handle_error.call_args
        self.assertEqual(500, args[1])
        self.assertEqual(self.project_id1, kwargs['project_id'])
        self.assertEqual('project', kwargs['resource_type'])
        self.assertEqual('deleted', kwargs['operation_type'])
        # Make sure entities are still present after rollback
        db_secrets = self.repos.secret_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_secrets))
        self.assertEqual(secret_id, db_secrets[0].id)

        db_project_secret = (
            self.repos.project_secret_repo.get_project_entities(project1_id))
        self.assertEqual(1, len(db_project_secret))

        db_kek = self.repos.kek_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_kek))

        db_project = self.repos.project_repo.get_project_entities(project1_id)
        self.assertEqual(1, len(db_project))
