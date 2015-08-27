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
import datetime
import functools

try:
    import newrelic.agent
    from newrelic.api import application
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo_service import service

from barbican.common import config
from barbican.common import utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories
from barbican import queue
from barbican.tasks import common
from barbican.tasks import resources

if newrelic_loaded:
    newrelic.agent.initialize('/etc/newrelic/newrelic.ini')

LOG = utils.getLogger(__name__)

CONF = config.CONF


# Maps the common/shared RetryTasks (returned from lower-level business logic
# and plugin processing) to top-level RPC tasks in the Tasks class below.
MAP_RETRY_TASKS = {
    common.RetryTasks.INVOKE_CERT_STATUS_CHECK_TASK: 'check_certificate_status'
}


def find_function_name(func, if_no_name=None):
    """Returns pretty-formatted function name."""
    return getattr(func, '__name__', if_no_name)


def retryable_order(fn):
    """Provides retry/scheduling support to Order-related tasks."""

    @functools.wraps(fn)
    def wrapper(method_self, *args, **kwargs):
        result = fn(method_self, *args, **kwargs)
        retry_rpc_method = schedule_order_retry_tasks(
            fn, result, *args, **kwargs)
        if retry_rpc_method:
            LOG.info(
                u._LI("Scheduled RPC method for retry: '%s'"),
                retry_rpc_method)
        else:
            LOG.info(
                u._LI("Task '%s' did not have to be retried"),
                find_function_name(fn, if_no_name='???'))

    return wrapper


def transactional(fn):
    """Provides request-scoped database transaction support to tasks."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        fn_name = find_function_name(fn, if_no_name='???')

        if not queue.is_server_side():
            # Non-server mode directly invokes tasks.
            fn(*args, **kwargs)
            LOG.info(u._LI("Completed worker task: '%s'"), fn_name)
        else:
            # Manage session/transaction.
            try:
                fn(*args, **kwargs)
                repositories.commit()
                LOG.info(
                    u._LI("Completed worker task (post-commit): '%s'"),
                    fn_name)
            except Exception:
                """NOTE: Wrapped functions must process with care!

                Exceptions that reach here will revert the entire transaction,
                including any updates made to entities such as setting error
                codes and error messages.
                """
                LOG.exception(
                    u._LE("Problem seen processing worker task: '%s'"),
                    fn_name
                )
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


def schedule_order_retry_tasks(
        invoked_task, retry_result, context, *args, **kwargs):
    """Schedules an Order-related task for retry.

    :param invoked_task: The RPC method that was just invoked.
    :param retry_result: A :class:`FollowOnProcessingStatusDTO` if follow-on
                         processing (such as retrying this or another task) is
                         required, otherwise None indicates no such follow-on
                         processing is required.
    :param context: Queue context, not used.
    :param order_id: ID of the Order entity the task to retry is for.
    :param args: List of arguments passed in to the just-invoked task.
    :param kwargs: Dict of arguments passed in to the just-invoked task.
    :return: Returns the RPC task method scheduled for a retry, None if no RPC
             task was scheduled.
    """

    retry_rpc_method = None
    order_id = kwargs.get('order_id')

    if not retry_result or not order_id:
        pass

    elif common.RetryTasks.INVOKE_SAME_TASK == retry_result.retry_task:
        if invoked_task:
            retry_rpc_method = find_function_name(invoked_task)

    else:
        retry_rpc_method = MAP_RETRY_TASKS.get(retry_result.retry_task)

    if retry_rpc_method:
        LOG.debug(
            'Scheduling RPC method for retry: {0}'.format(retry_rpc_method))

        date_to_retry_at = datetime.datetime.utcnow() + datetime.timedelta(
            milliseconds=retry_result.retry_msec)

        retry_model = models.OrderRetryTask()
        retry_model.order_id = order_id
        retry_model.retry_task = retry_rpc_method
        retry_model.retry_at = date_to_retry_at
        retry_model.retry_args = args
        retry_model.retry_kwargs = kwargs
        retry_model.retry_count = 0

        retry_repo = repositories.get_order_retry_tasks_repository()
        retry_repo.create_from(retry_model)

    return retry_rpc_method


class Tasks(object):
    """Tasks that can be invoked asynchronously in Barbican.

    Only place task methods and implementations on this class, as they can be
    called directly from the client side for non-asynchronous standalone
    single-node operation.

    If a new method is added that can be retried, please also add its method
    name to MAP_RETRY_TASKS above.

    The TaskServer class below extends this class to implement a worker-side
    server utilizing Oslo messaging's RPC server. This RPC server can invoke
    methods on itself, which include the methods in this class.
    """

    @monitored
    @transactional
    @retryable_order
    def process_type_order(self, context, order_id, project_id, request_id):
        """Process TypeOrder."""
        message = u._LI(
            "Processing type order:  "
            "order ID is '%(order)s' and request ID is '%(request)s'"
        )
        LOG.info(message, {'order': order_id, 'request': request_id})
        return resources.BeginTypeOrder().process_and_suppress_exceptions(
            order_id, project_id)

    @monitored
    @transactional
    @retryable_order
    def update_order(self, context, order_id, project_id,
                     updated_meta, request_id):
        """Update Order."""
        message = u._LI(
            "Processing update order: "
            "order ID is '%(order)s' and request ID is '%(request)s'"
        )
        LOG.info(message, {'order': order_id, 'request': request_id})
        return resources.UpdateOrder().process_and_suppress_exceptions(
            order_id, project_id, updated_meta)

    @monitored
    @transactional
    @retryable_order
    def check_certificate_status(self, context, order_id,
                                 project_id, request_id):
        """Check the status of a certificate order."""
        message = u._LI(
            "Processing check certificate status on order: "
            "order ID is '%(order)s' and request ID is '%(request)s'"
        )

        LOG.info(message, {'order': order_id, 'request': request_id})
        check_cert_order = resources.CheckCertificateStatusOrder()
        return check_cert_order.process_and_suppress_exceptions(
            order_id, project_id)


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
        LOG.info(u._LI("Starting the TaskServer"))
        self._server.start()
        super(TaskServer, self).start()

    def stop(self):
        LOG.info(u._LI("Halting the TaskServer"))
        super(TaskServer, self).stop()
        self._server.stop()
