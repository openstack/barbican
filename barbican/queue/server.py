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
import functools

try:
    import newrelic.agent
    from newrelic.api import application
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo_config import cfg

from barbican.common import utils
from barbican.model import repositories
from barbican.openstack.common import service
from barbican import queue
from barbican.tasks import resources

if newrelic_loaded:
    newrelic.agent.initialize('/etc/newrelic/newrelic.ini')

LOG = utils.getLogger(__name__)

CONF = cfg.CONF


def transactional(fn):
    """Provides request-scoped database transaction support to tasks."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not queue.is_server_side():
            fn(*args, **kwargs)  # Non-server mode directly invokes tasks.
        else:
            # Manage session/transaction.
            try:
                fn(*args, **kwargs)
                repositories.commit()
            except Exception:
                """NOTE: Wrapped functions must process with care!

                Exceptions that reach here will revert the entire transaction,
                including any updates made to entities such as setting error
                codes and error messages.
                """
                repositories.rollback()
            finally:
                repositories.clear()

    return wrapper


def monitored(fn):  # pragma: no cover
    """Provides monitoring capabilities for task methods."""
    # TODO(jvrbanac): Figure out how we should test third-party monitoring

    # Support NewRelic Monitoring
    if newrelic_loaded:
        # Create a NewRelic app instance
        app = application.application_instance()

        def newrelic_wrapper(*args, **kwargs):
            # Resolve real name since decorators are wrapper the method
            if len(args) > 0 and hasattr(args[0], fn.__name__):
                cls = type(args[0])
                task_name = '{0}:{1}.{2}'.format(
                    cls.__module__,
                    cls.__name__,
                    fn.__name__
                )
            else:
                task_name = newrelic.agent.callable_name(fn)

            # Execute task under a monitored context
            with newrelic.agent.BackgroundTask(app, task_name):
                fn(*args, **kwargs)

        return newrelic_wrapper

    return fn


class Tasks(object):
    """Tasks that can be invoked asynchronously in Barbican.

    Only place task methods and implementations on this class, as they can be
    called directly from the client side for non-asynchronous standalone
    single-node operation.

    The TaskServer class below extends this class to implement a worker-side
    server utilizing Oslo messaging's RPC server. This RPC server can invoke
    methods on itself, which include the methods in this class.
    """

    @monitored
    @transactional
    def process_type_order(self, context, order_id, project_id):
        """Process TypeOrder."""
        LOG.info('Processing TypeOrder: {0}'.format(order_id))
        task = resources.BeginTypeOrder()
        try:
            task.process(order_id, project_id)
        except Exception:
            LOG.exception(">>>>> Task exception seen, details reported "
                          "on the Orders entity.")

    @monitored
    @transactional
    def update_order(self, context, order_id, project_id, updated_meta):
        """Update Order."""
        LOG.info('Updating TypeOrder: {0}'.format(order_id))
        task = resources.UpdateOrder()
        try:
            task.process(order_id, project_id, updated_meta)
        except Exception:
            LOG.exception(">>>>> Task exception seen, details reported "
                          "on the Orders entity.")


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

        # Setting up db engine to avoid lazy initialization
        repositories.setup_database_engine_and_factory()

        # This property must be defined for the 'endpoints' specified below,
        #   as the oslo_messaging RPC server will ask for it.
        self.target = queue.get_target()

        # Create an oslo RPC server, that calls back on to this class
        #   instance to invoke tasks, such as 'process_order()' on the
        #   extended Tasks class above.
        self._server = queue.get_server(target=self.target,
                                        endpoints=[self])

    def start(self):
        LOG.info("Starting the TaskServer")
        self._server.start()
        super(TaskServer, self).start()

    def stop(self):
        LOG.info("Halting the TaskServer")
        super(TaskServer, self).stop()
        self._server.stop()
