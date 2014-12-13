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
from barbican.tests import database_utils


class WhenTestingProjectRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingProjectRepository, self).setUp()
        self.repo = repositories.ProjectRepo()

    def test_should_create_retrieve_deleted_project(self):
        session = self.repo.get_session()

        project = models.Project()
        project.keystone_id = 'my keystone id'
        project.status = models.States.ACTIVE
        self.repo.create_from(project, session=session)
        self.assertIsNotNone(project.id)
        self.assertFalse(project.deleted)

        project_get = self.repo.get(project.id)
        self.assertEqual(project.id, project_get.id)

        self.repo.delete_entity_by_id(project.id, 'my keystone id')
        self.assertTrue(project.deleted)

    def test_should_raise_no_result_found(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.find_by_external_project_id,
            "my keystone id",
            session=session,
            suppress_exception=False)
