# Copyright (c) 2015 Rackspace, Inc.
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

"""
Retry/scheduler classes and logic.
"""
import datetime
import random

import oslo_messaging as messaging
from oslo_service import service
from oslo_utils import timeutils
from sqlalchemy import exc as sa_exc

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories
from barbican.queue import client as async_client

LOG = utils.getLogger(__name__)

CONF = config.CONF


def _compute_next_periodic_interval():
    periodic_interval = (
        CONF.retry_scheduler.periodic_interval_max_seconds
    )

    # Return +- 20% of interval.
    return random.uniform(0.8 * periodic_interval,  # nosec
                          1.2 * periodic_interval)


class PeriodicServer(service.Service):
    """Server to process retry and scheduled tasks.

    This server is an Oslo service. This server runs a thread to periodically
    check tasks that need to be retried, and then sends them up to the RPC
    queue for later processing by a worker node.
    """
    def __init__(self, queue_resource=None):
        super(PeriodicServer, self).__init__()

        # Setting up db engine to avoid lazy initialization
        repositories.setup_database_engine_and_factory()

        # Connect to the worker queue, to send retry RPC tasks to it later.
        self.queue = queue_resource or async_client.TaskClient()

        # Start the task retry periodic scheduler process up.
        periodic_interval = (
            CONF.retry_scheduler.periodic_interval_max_seconds
        )
        self.tg.add_dynamic_timer(
            self._check_retry_tasks,
            initial_delay=CONF.retry_scheduler.initial_delay_seconds,
            periodic_interval_max=periodic_interval)

        self.order_retry_repo = repositories.get_order_retry_tasks_repository()
        self.cleanup_repo = (
            repositories.get_secret_store_cleanup_tasks_repository())

    def start(self):
        LOG.info("Starting the PeriodicServer")
        super(PeriodicServer, self).start()

    def stop(self, graceful=True):
        LOG.info("Halting the PeriodicServer")
        super(PeriodicServer, self).stop(graceful=graceful)

    def _check_retry_tasks(self):
        """Periodically check to see if tasks need to be scheduled.

        :return: Return the number of seconds to wait before invoking this
            method again.
        """
        total_tasks_processed = 0
        try:
            total_tasks_processed = self._process_retry_tasks()
        except Exception:
            LOG.exception("Problem seen processing scheduled retry tasks")

        # Return the next delay before this method is invoked again.
        check_again_in_seconds = _compute_next_periodic_interval()
        LOG.info("Done processing '%(total)s' tasks, will check again in "
                 "'%(next)s' seconds.",
                 {
                     'total': total_tasks_processed,
                     'next': check_again_in_seconds
                 }
                 )
        return check_again_in_seconds

    def _process_retry_tasks(self):
        """Scan for and then re-queue tasks that are ready to retry."""
        LOG.info("Processing scheduled retry tasks:")

        # Retrieve tasks to retry.
        entities, total = self._retrieve_tasks()

        # Create RPC tasks for each retry task found.
        for task in entities:
            self._enqueue_task(task)

        cleanup_entities, cleanup_total = self._retrieve_cleanup_tasks()
        for task in cleanup_entities:
            self._enqueue_cleanup_task(task)

        return total + cleanup_total

    def _retrieve_tasks(self):
        """Retrieve a list of tasks to retry."""
        repositories.start()
        try:
            entities, _, _, total = self.order_retry_repo.get_by_create_date(
                only_at_or_before_this_date=timeutils.utcnow(),
                suppress_exception=True)
        finally:
            repositories.clear()

        return entities, total

    def _enqueue_task(self, task):
        """Re-enqueue the specified task."""
        retry_task_name = 'N/A'
        retry_args = 'N/A'
        retry_kwargs = 'N/A'

        # Start a new isolated database transaction just for this task.
        repositories.start()
        try:
            # Invoke queue client to place retried RPC task on queue.
            retry_task_name = task.retry_task
            retry_args = task.retry_args
            retry_kwargs = task.retry_kwargs
            retry_method = getattr(self.queue, retry_task_name)
            retry_method(*retry_args, **retry_kwargs)

            # Remove the retry record from the queue.
            task.status = models.States.ACTIVE
            self.order_retry_repo.delete_entity_by_id(task.id, None)

            repositories.commit()

            LOG.debug(
                "(Enqueued method '{0}' with args '{1}' and "
                "kwargs '{2}')".format(
                    retry_task_name, retry_args, retry_kwargs))
        except Exception:
            LOG.exception("Problem enqueuing method '%(name)s' with args "
                          "'%(args)s' and kwargs '%(kwargs)s'.",
                          {
                              'name': retry_task_name,
                              'args': retry_args,
                              'kwargs': retry_kwargs
                          }
                          )
            repositories.rollback()
        finally:
            repositories.clear()

    def _retrieve_cleanup_tasks(self):
        """Retrieve due secret-store plugin cleanup-task rows."""
        repositories.start()
        try:
            entities, _, _, total = self.cleanup_repo.get_due(
                only_at_or_before_this_date=timeutils.utcnow(),
                suppress_exception=True)
        finally:
            repositories.clear()

        return entities, total

    def _enqueue_cleanup_task(self, task):
        """Re-enqueue a cleanup task without deleting the task row.

        The worker owns completion (soft-delete or ERROR). retry_at is
        bumped here so a later scheduler pass does not stampede while
        the worker is still running.
        """
        task_id = task.id
        repositories.start()
        try:
            live = self.cleanup_repo.get(
                entity_id=task_id, suppress_exception=True)
            if (not live or live.deleted or
                    live.status == models.States.ERROR):
                repositories.commit()
                return

            delay_msec = (
                CONF.retry_scheduler.secret_store_cleanup_retry_msec)
            live.retry_at = timeutils.utcnow() + datetime.timedelta(
                milliseconds=delay_msec)
            self.cleanup_repo.save(live)
            repositories.commit()

            self.queue.cleanup_secret_store_object(task_id=task_id)
            # When [queue] enable=False, TaskClient uses DirectTaskInvoker
            # in this process with is_server_side=False, so @transactional
            # does not commit. Persist soft-delete / reschedule here.
            # With RPC enabled this is an empty commit (worker commits).
            repositories.commit()
            LOG.debug(
                "Enqueued secret-store cleanup task '%s'", task_id)
        except (messaging.MessagingException, sa_exc.SQLAlchemyError,
                exception.BarbicanException):
            # Narrower than Exception: unexpected bugs should surface.
            # Messaging/DB failures roll back this task's transaction;
            # the cleanup-task row remains for a later scheduler pass.
            LOG.exception(
                "Problem enqueuing secret-store cleanup task '%s'",
                task_id)
            repositories.rollback()
        finally:
            repositories.clear()
