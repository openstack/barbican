# Copyright (c) 2015 Rackspace, Inc.
#
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
import time

from barbican.common import config
from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingOrderRetryTaskRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingOrderRetryTaskRepository, self).setUp()

        self.date_time_now = datetime.datetime.utcnow()
        self.test_args = ['test', 'args']
        self.test_kwargs = {'test': 1, 'kwargs': 2}

        self.repo = repositories.OrderRetryTaskRepo()
        self.order_repo = repositories.OrderRepo()

    def test_get_order_retry_task(self):
        session = self.repo.get_session()

        order_retry_task = self._create_retry_task(session)

        order_retry_task_from_get = self.repo.get(
            order_retry_task.id,
            session=session,
        )

        self.assertEqual(order_retry_task.id, order_retry_task_from_get.id)
        self.assertEqual(
            self.date_time_now, order_retry_task_from_get.retry_at)
        self.assertEqual(u'retry-task', order_retry_task_from_get.retry_task)
        self.assertEqual(self.test_args, order_retry_task_from_get.retry_args)
        self.assertEqual(self.test_kwargs,
                         order_retry_task_from_get.retry_kwargs)

    def test_get_order_retry_task_filtered_by_retry_time(self):
        session = self.repo.get_session()

        future_seconds = 3
        date_time_future = (
            self.date_time_now + datetime.timedelta(seconds=future_seconds)
        )

        order_retry_task = self._create_retry_task(
            session, retry_at=date_time_future)

        # A retrieve by the current time should return no entries, as the only
        # retry record is set into the future.
        entities, offset, limit, total = self.repo.get_by_create_date(
            only_at_or_before_this_date=self.date_time_now,
            session=session,
            suppress_exception=True
        )
        self.assertEqual(0, total)
        self.assertEqual([], entities)

        # Wait until the future time is the current time.
        time.sleep(2 * future_seconds)

        # Now, a retrieve by the current time should return our entry.
        entities, offset, limit, total = self.repo.get_by_create_date(
            only_at_or_before_this_date=datetime.datetime.utcnow(),
            session=session,
            suppress_exception=True
        )
        self.assertEqual(1, total)

        # Verify that retry task record is what we put in originally.
        order_retry_task_from_get = entities[0]
        self.assertEqual(order_retry_task.id, order_retry_task_from_get.id)
        self.assertEqual(date_time_future, order_retry_task_from_get.retry_at)
        self.assertEqual(u'retry-task', order_retry_task_from_get.retry_task)
        self.assertEqual(self.test_args, order_retry_task_from_get.retry_args)
        self.assertEqual(self.test_kwargs,
                         order_retry_task_from_get.retry_kwargs)

    def test_should_raise_no_result_found_no_exception(self):
        session = self.repo.get_session()

        entities, offset, limit, total = self.repo.get_by_create_date(
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
            session=session,
            suppress_exception=False)

    def _create_retry_task(self, session, retry_at=None):
        project = database_utils.create_project(session=session)
        order = database_utils.create_order(project, session=session)

        order_retry_task = models.OrderRetryTask()
        order_retry_task.order_id = order.id
        order_retry_task.retry_task = u'retry-task'
        order_retry_task.retry_at = retry_at or self.date_time_now
        order_retry_task.retry_args = self.test_args
        order_retry_task.retry_kwargs = self.test_kwargs
        self.repo.create_from(order_retry_task, session=session)

        session.commit()

        return order_retry_task
