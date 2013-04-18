# Copyright (c) 2013 Rackspace, Inc.
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
Celery Queue Resources related objects and functions.
"""
from celery import Celery

from oslo.config import cfg
from barbican.tasks.resources import BeginCSR
from barbican.common import config, utils


LOG = utils.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('sql_connection', 'barbican.model.repositories')

# Celery instance used by client to register @celery.task's and by
#   the bin/barbican-worker to boot up a Celery worker server instance.
celery = Celery('barbican.queue.celery.resources',
                broker='amqp://guest@localhost//',
                # backend='amqp://',
                include=['barbican.queue.celery.resources'])


def begin_csr(csr_id):
    return begin_csr_wrapper.delay(csr_id)


@celery.task
def begin_csr_wrapper(csr_id):
    """Process the beginning of CSR processing."""
    LOG.debug('CSR id is {0}'.format(csr_id))
    task = BeginCSR()
    return task.process(csr_id)
