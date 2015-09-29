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

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils as utils


class WhenTestingContainerConsumerRepository(utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingContainerConsumerRepository, self).setUp()
        self.repo = repositories.ContainerConsumerRepo()
        self.repo_container = repositories.ContainerRepo()

    def test_should_update_with_duplicate_consumer(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        container = models.Container()
        container.project_id = project.id
        container.save(session=session)

        # Create a consumer.
        consumer = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name', 'URL': 'www.foo.com'})
        consumer.save(session=session)

        # Commit things so far, because the 'create_or_update_from' call below
        # will handle consumer metadata with same composite key items already
        # existing, and then rollback this session's transaction, which would
        # remove the items added above and result in a not-found error below.
        session.commit()

        # Try to create a consumer on the container...should re-use the
        # one added above.
        consumer2 = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name', 'URL': 'www.foo.com'})
        self.repo.create_or_update_from(consumer2, container, session=session)

        container2 = self.repo_container.get(
            container.id, project.external_id, session=session)
        self.assertEqual(1, len(container2.consumers))

    def test_should_raise_duplicate_create_same_composite_key_no_id(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        container = models.Container()
        container.project_id = project.id
        container.save(session=session)

        # Create a consumer.
        consumer = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name', 'URL': 'www.foo.com'})
        consumer.save(session=session)

        # Commit things so far, because the 'create_from' call below will
        # handle consumer metadata with same composite key items already
        # existing, and then rollback this session's transaction, which would
        # remove the items added above and result in a not-found error below.
        session.commit()

        # Create a new entity with the same composite key as the first one.
        consumer2 = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name', 'URL': 'www.foo.com'})

        exception_result = self.assertRaises(
            exception.Duplicate,
            self.repo.create_from,
            consumer2,
            session=session)
        self.assertEqual(
            "Entity 'ContainerConsumer' already exists",
            exception_result.message)

    def test_should_raise_no_result_found_get_container_id(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_container_id,
            "my container id",
            session=session,
            suppress_exception=False)

    def test_should_raise_no_result_found_get_by_values_no_deleted(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_values,
            "my container id",
            "name",
            "url",
            session=session,
            suppress_exception=False,
            show_deleted=False)

    def test_should_raise_no_result_found_get_by_values_show_deleted(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_values,
            "my container id",
            "name",
            "url",
            session=session,
            suppress_exception=False,
            show_deleted=True)

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

        container = models.Container()
        container.project_id = project.id
        container.save(session=session)

        consumer = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name', 'URL': 'www.foo.com'})
        consumer.save(session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)

    def test_should_get_count_one_after_delete(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        container = models.Container()
        container.project_id = project.id
        container.save(session=session)

        consumer = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name1', 'URL': 'www.foo.com'})
        consumer.save(session=session)

        consumer = models.ContainerConsumerMetadatum(
            container.id, project.id, {'name': 'name2', 'URL': 'www.foo.com'})
        consumer.save(session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(2, count)

        self.repo.delete_entity_by_id(consumer.id, "my keystone id",
                                      session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)
