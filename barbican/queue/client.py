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
Client-side (i.e. API side) classes and logic.
"""
from barbican.common import utils
from barbican import queue
from barbican.queue import server

LOG = utils.getLogger(__name__)


class TaskClient(object):
    """API-side client interface to asynchronous queuing services.

    The class delegates calls to the oslo_messaging RPC framework.
    """
    def __init__(self):
        super(TaskClient, self).__init__()

        # Establish either an asynchronous messaging/queuing client
        #   interface (via Oslo's RPC messaging) or else allow for
        #   synchronously invoking worker processes in support of a
        #   standalone single-node mode for Barbican.
        self._client = queue.get_client() or _DirectTaskInvokerClient()

    def process_type_order(self, order_id, project_id, request_id):
        """Process TypeOrder."""

        self._cast('process_type_order',
                   order_id=order_id,
                   project_id=project_id,
                   request_id=request_id)

    def update_order(self, order_id, project_id, updated_meta, request_id):
        """Update Order."""

        self._cast('update_order',
                   order_id=order_id,
                   project_id=project_id,
                   updated_meta=updated_meta,
                   request_id=request_id)

    def check_certificate_status(self, order_id, project_id, request_id):
        """Check the status of a certificate order."""
        self._cast('check_certificate_status',
                   order_id=order_id,
                   project_id=project_id,
                   request_id=request_id)

    def _cast(self, name, **kwargs):
        """Asynchronous call handler. Barbican probably only needs casts.

        :param name: Method name to invoke.
        :param kwargs: Arguments for the method invocation.
        :return:
        """
        return self._client.cast({}, name, **kwargs)

    def _call(self, name, **kwargs):
        """Synchronous call handler. Barbican probably *never* uses calls."""
        return self._client.call({}, name, **kwargs)


class _DirectTaskInvokerClient(object):
    """Allows for direct invocation of queue.server Tasks.

    This class supports a standalone single-node mode of operation for
    Barbican, whereby typically asynchronous requests to Barbican are
    handled synchronously.
    """

    def __init__(self):
        super(_DirectTaskInvokerClient, self).__init__()

        self._tasks = server.Tasks()

    def cast(self, context, method_name, **kwargs):
        try:
            getattr(self._tasks, method_name)(context, **kwargs)
        except Exception:
            LOG.exception(">>>>> Task exception seen for synchronous task "
                          "invocation, so handling exception to mimic "
                          "asynchronous behavior.")

    def call(self, context, method_name, **kwargs):
        raise ValueError("No support for call() client methods.")
