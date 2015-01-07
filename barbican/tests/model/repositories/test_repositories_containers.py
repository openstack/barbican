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
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingContainerRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingContainerRepository, self).setUp()
        self.repo = repositories.ContainerRepo()

    def test_should_raise_no_result_found(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_create_date,
            "my keystone id",
            session=session,
            suppress_exception=False)
