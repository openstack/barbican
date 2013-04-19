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

opt_group = cfg.OptGroup(name='celery',
                         title='Options for Celery queue interface')

celery_opts = [
    cfg.StrOpt('project', default='barbican.queue.celery.resources'),
    cfg.StrOpt('broker', default='amqp://guest@localhost//'),
    cfg.StrOpt('include', default='barbican.queue.celery.resources'),
]

CONF = cfg.CONF
CONF.register_group(opt_group)
CONF.register_opts(celery_opts, opt_group)
CONF.import_opt('debug', 'barbican.openstack.common.log')


# Celery instance used by client to register @celery.task's and by
#   the bin/barbican-worker to boot up a Celery worker server instance.
celery = Celery(CONF.celery.project,
                broker=CONF.celery.broker,
                # backend='amqp://',
                include=[CONF.celery.include])


def begin_csr(csr_id):
    """Process the beginning of CSR processing."""
    return begin_csr_wrapper.delay(csr_id)


@celery.task
def begin_csr_wrapper(csr_id):
    """(Celery wrapped task) Process the beginning of CSR processing."""
    LOG.debug('CSR id is {0}'.format(csr_id))
    task = BeginCSR()
    return task.process(csr_id)
