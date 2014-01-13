# Copyright (c) 2013-2014 Rackspace, Inc.
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
Server-side (i.e. worker side) classes and logic.
"""
from oslo.config import cfg

from barbican.common import utils
from barbican.openstack.common import service
from barbican.tasks import resources
from barbican import queue


LOG = utils.getLogger(__name__)

CONF = cfg.CONF


class Tasks(object):
    """Tasks that can be invoked asynchronously in Barbican.

    Only place task methods and implementations on this class, as they can be
    called directly from the client side for non-asynchronous standalone
    single-node operation.

    The TaskServer class below extends this class to implement a worker-side
    server utilizing Oslo messaging's RPC server. This RPC server can invoke
    methods on itself, which include the methods in this class.
    """
    def process_order(self, context, order_id, keystone_id):
        """Process Order."""
        LOG.debug('Order id is {0}'.format(order_id))
        task = resources.BeginOrder()
        try:
            task.process(order_id, keystone_id)
        except Exception:
            LOG.exception(">>>>> Task exception seen, details reported "
                          "on the Orders entity.")

    def process_verification(self, context, verification_id, keystone_id):
        """Process Verification."""
        LOG.debug('Verification id is {0}'.format(verification_id))
        task = resources.PerformVerification()
        try:
            task.process(verification_id, keystone_id)
        except Exception:
            LOG.exception(">>>>> Task exception seen, details reported "
                          "on the the Verification entity.")


class TaskServer(Tasks, service.Service):
    """Server to process asynchronous tasking from Barbican API nodes.

    This server is an Oslo service that exposes task methods that can
    be invoked from the Barbican API nodes. It delegates to an Oslo
    RPC messaging server to invoke methods asynchronously on this class.
    Since this class also extends the Tasks class above, its task-based
    methods are hence available to the RPC messaging server.
    """
    def __init__(self):
        super(TaskServer, self).__init__()

        # This property must be defined for the 'endpoints' specified below,
        #   as the oslo.messaging RPC server will ask for it.
        self.target = queue.get_target()

        # Create an oslo RPC server, that calls back on to this class
        #   instance to invoke tasks, such as 'process_order()' on the
        #   extended Tasks class above.
        self._server = queue.get_server(target=self.target,
                                        endpoints=[self])

    def start(self):
        self._server.start()
        super(TaskServer, self).start()

    def stop(self):
        super(TaskServer, self).stop()
        self._server.stop()
