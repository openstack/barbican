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

from barbican.common import config
from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingOrderRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingOrderRepository, self).setUp()
        self.repo = repositories.OrderRepo()

    def test_should_raise_no_result_found_no_exception(self):
        session = self.repo.get_session()

        entities, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            session=session,
            suppress_exception=True)

        self.assertEqual([], entities)
        self.assertEqual(0, offset)
        self.assertEqual(config.CONF.default_limit_paging, limit)
        self.assertEqual(0, total)

    def test_should_raise_no_result_found_with_exceptions(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_create_date,
            "my keystone id",
            session=session,
            suppress_exception=False)

    def test_get_order(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        order = models.Order()
        order.project_id = project.id
        self.repo.create_from(order, session=session)

        session.commit()

        order_from_get = self.repo.get(
            order.id,
            external_project_id="my keystone id",
            session=session,
        )

        self.assertEqual(order.id, order_from_get.id)

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

        order_model = models.Order()
        order_model.project_id = project.id
        self.repo.create_from(order_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)

        self.assertEqual(1, count)

    def test_should_get_count_one_after_delete(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        order_model = models.Order()
        order_model.project_id = project.id
        self.repo.create_from(order_model, session=session)

        order_model = models.Order()
        order_model.project_id = project.id
        self.repo.create_from(order_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(2, count)

        self.repo.delete_entity_by_id(order_model.id, "my keystone id",
                                      session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)
