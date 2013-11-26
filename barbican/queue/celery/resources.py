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
from barbican.tasks import resources
from barbican.common import utils


LOG = utils.getLogger(__name__)

opt_group = cfg.OptGroup(name='celery',
                         title='Options for Celery queue interface')

celery_opts = [
    cfg.StrOpt('project', default='barbican.queue.celery.resources'),
    cfg.ListOpt('broker', default=['amqp://guest@localhost//']),
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
                include=[CONF.celery.include])


def process_order(order_id, keystone_id):
    """Process Order."""
    return process_order_wrapper.delay(order_id, keystone_id)


def process_verification(verification_id, keystone_id):
    """Process Verification."""
    return process_verification_wrapper.delay(verification_id, keystone_id)


@celery.task
def process_order_wrapper(order_id, keystone_id):
    """(Celery wrapped task) Process Order."""
    LOG.debug('Order id is {0}'.format(order_id))
    task = resources.BeginOrder()
    return task.process(order_id, keystone_id)


@celery.task
def process_verification_wrapper(verification_id, keystone_id):
    """(Celery wrapped task) Process Verification."""
    LOG.debug('Verification id is {0}'.format(verification_id))
    task = resources.PerformVerification()
    return task.process(verification_id, keystone_id)
