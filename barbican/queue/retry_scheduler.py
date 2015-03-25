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
from oslo_config import cfg

from barbican.common import utils
from barbican import i18n as u
from barbican.model import repositories
from barbican.openstack.common import periodic_task
from barbican.openstack.common import service
from barbican.queue import client as async_client

LOG = utils.getLogger(__name__)

retry_opt_group = cfg.OptGroup(name='retry_scheduler',
                               title='Retry/Scheduler Options')

retry_opts = [
    cfg.FloatOpt(
        'task_retry_tg_initial_delay', default=10.0,
        help=u._('Seconds (float) to wait before starting retry scheduler')),
    cfg.FloatOpt(
        'task_retry_tg_periodic_interval_max', default=10.0,
        help=u._('Seconds (float) to wait between periodic schedule events')),
]

CONF = cfg.CONF
CONF.register_group(retry_opt_group)
CONF.register_opts(retry_opts, group=retry_opt_group)


class PeriodicServer(service.Service):
    """Server to process retry and scheduled tasks.

    This server is an Oslo periodic-task service (see
    http://docs.openstack.org/developer/oslo-incubator/api/openstack.common
    .periodic_task.html). On a periodic basis, this server checks for tasks
    that need to be retried, and then sends them up to the RPC queue for later
    processing by a worker node.
    """
    def __init__(self, queue_resource=None):
        super(PeriodicServer, self).__init__()

        # Setting up db engine to avoid lazy initialization
        repositories.setup_database_engine_and_factory()

        # Connect to the worker queue, to send retry RPC tasks to it later.
        self.queue = queue_resource or async_client.TaskClient()

        # Start the task retry periodic scheduler process up.
        periodic_interval = (
            CONF.retry_scheduler.task_retry_tg_periodic_interval_max
        )
        self.tg.add_dynamic_timer(
            self._check_retry_tasks,
            initial_delay=CONF.retry_scheduler.task_retry_tg_initial_delay,
            periodic_interval_max=periodic_interval)

    def start(self):
        LOG.info("Starting the PeriodicServer")
        super(PeriodicServer, self).start()

    def stop(self, graceful=True):
        LOG.info("Halting the PeriodicServer")
        super(PeriodicServer, self).stop(graceful=graceful)

    @periodic_task.periodic_task
    def _check_retry_tasks(self):
        """Periodically check to see if tasks need to be scheduled."""
        LOG.debug("Processing scheduled retry tasks")

        # Return the next delay before this method is invoked again
        # TODO(john-wood-w) A future CR will fill in the blanks here.
        return 60.0
