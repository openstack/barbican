#    Copyright (c) 2019 Red Hat, inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils as utils


class WhenTestingSecretConsumerRepository(utils.RepositoryTestCase):
    def setUp(self):
        super(WhenTestingSecretConsumerRepository, self).setUp()

        self.secret_repo = repositories.get_secret_repository()
        self.consumer_repo = repositories.get_secret_consumer_repository()
        self.session = self.consumer_repo.get_session()
        self.project = utils.create_project(session=self.session)
        self.secret = self._create_secret()

        self.session.commit()

    def _create_secret(self):
        return utils.create_secret(self.project, session=self.session)

    def _create_consumer(self, secret=None, resource_id=0):
        if secret is None:
            secret = self.secret

        return utils.create_secret_consumer(
            secret,
            resource_id="resource_id_{}".format(resource_id),
            session=self.session,
        )

    def _count_consumers(self):
        return self.consumer_repo.get_count(
            self.project.id, session=self.session
        )

    def test_should_raise_no_result_found_get_by_secret_id(self):
        self.assertRaises(
            exception.NotFound,
            self.consumer_repo.get_by_secret_id,
            self.secret.id,
            session=self.session,
        )

    def test_get_by_secret_id(self):
        for resource_id in [1, 2, 3]:
            self._create_consumer(resource_id=resource_id)

        self.assertEqual(
            3, self.consumer_repo.get_by_secret_id(self.secret.id)[3]
        )

    def test_should_raise_no_result_found_get_by_resource_id(self):
        self.assertRaises(
            exception.NotFound,
            self.consumer_repo.get_by_resource_id,
            "my resource id",
            session=self.session,
        )

    def test_get_by_resource_id(self):
        secret1 = self._create_secret()
        secret2 = self._create_secret()
        secret3 = self._create_secret()

        for secret in [secret1, secret2, secret3]:
            self._create_consumer(secret=secret)

        self.assertEqual(
            3, self.consumer_repo.get_by_resource_id("resource_id_0")[3]
        )

    def test_should_update_with_duplicate_consumer(self):
        consumer1 = self._create_consumer()
        self.assertEqual(1, len(self.secret.consumers))

        # Commit things so far, because the 'create_or_update_from' call below
        # will handle consumer metadata with same composite key items already
        # existing, and then rollback this session's transaction, which would
        # remove the items added above and result in a not-found error below.
        self.session.commit()

        consumer2 = models.SecretConsumerMetadatum(
            secret_id=consumer1.secret_id,
            project_id=consumer1.project_id,
            service=consumer1.service,
            resource_type=consumer1.resource_type,
            resource_id=consumer1.resource_id,
        )

        self.consumer_repo.create_or_update_from(
            consumer2, self.secret, self.session
        )

        secret = self.secret_repo.get_secret_by_id(
            self.secret.id, session=self.session
        )
        self.assertEqual(1, len(secret.consumers))

    def test_should_raise_constraint_create_same_composite_key_no_id(self):
        self._create_consumer()

        exception_result = self.assertRaises(
            exception.ConstraintCheck, self._create_consumer
        )
        self.assertIn(
            "SQL constraint check failed", str(exception_result)
        )

    def test_should_get_count_zero(self):
        self.assertEqual(0, self._count_consumers())

    def test_should_get_count_one(self):
        self._create_consumer()
        self.assertEqual(1, self._count_consumers())

    def test_should_get_count_one_after_delete(self):
        consumer1 = self._create_consumer(resource_id=1)
        self._create_consumer(resource_id=2)
        self.assertEqual(2, self._count_consumers())

        self.consumer_repo.delete_entity_by_id(
            consumer1.id, consumer1.project_id, session=self.session
        )
        self.assertEqual(1, self._count_consumers())
