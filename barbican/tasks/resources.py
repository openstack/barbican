# Copyright (c) 2013-2015 Rackspace, Inc.
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
Task resources for the Barbican API.
"""
import abc

from barbican import api
from barbican.common import utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as rep
from barbican.plugin import resources as plugin
from barbican.tasks import certificate_resources as cert
from barbican.tasks import common


LOG = utils.getLogger(__name__)


class BaseTask(object, metaclass=abc.ABCMeta):
    """Base asynchronous task."""

    @abc.abstractmethod
    def get_name(self):
        """Localized task name

        A hook method to return a short localized name for this task.
        The returned name in the form 'u.('Verb Noun')'. For example:
            u._('Create Secret')
        """

    def process_and_suppress_exceptions(self, *args, **kwargs):
        """Invokes the process() template method, suppressing all exceptions.

        TODO(john-wood-w) This method suppresses exceptions for flows that
        do not want to rollback database modifications in reaction to such
        exceptions, as this could also rollback the marking of the entity
        (eg. order) in the ERROR status via the handle_error() call below.
        For Liberty, we might want to consider a workflow manager instead of
        these process_xxxx() method as shown here:
        https://gist.github.com/jfwood/a8130265b0db3c793ec8

        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: Returns :class:`FollowOnProcessingStatusDTO` if follow-on
                 processing (such as retrying this or another task) is
                 required, otherwise a None return indicates that no
                 follow-on processing is required.
        """
        try:
            return self.process(*args, **kwargs)
        except Exception:
            LOG.exception("Suppressing exception while trying to "
                          "process task '%s'.", self.get_name())

    def process(self, *args, **kwargs):
        """A template method for all asynchronous tasks.

        This method should not be overridden by sub-classes. Rather the
        abstract methods below should be overridden.

        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: Returns :class:`FollowOnProcessingStatusDTO` if follow-on
                 processing (such as retrying this or another task) is
                 required, otherwise a None return indicates that no
                 follow-on processing is required.
        """
        name = self.get_name()
        result = None

        # Retrieve the target entity (such as an models.Order instance).
        try:
            entity = self.retrieve_entity(*args, **kwargs)
        except Exception:
            # Serious error!
            LOG.exception("Could not retrieve information needed to "
                          "process task '%s'.", name)
            raise

        # Process the target entity.
        try:
            result = self.handle_processing(entity, *args, **kwargs)
        except Exception as e_orig:
            LOG.exception("Could not perform processing for task '%s'.", name)

            # Handle failure to process entity.
            try:
                status, message = api.generate_safe_exception_message(name,
                                                                      e_orig)
                self.handle_error(entity, status, message, e_orig,
                                  *args, **kwargs)
            except Exception:
                LOG.exception("Problem handling an error for task '%s', "
                              "raising original exception.", name)
            raise e_orig

        # Handle successful conclusion of processing.
        try:
            self.handle_success(entity, result, *args, **kwargs)
        except Exception:
            LOG.exception("Could not process after successfully "
                          "executing task '%s'.", name)
            raise
        return result

    @abc.abstractmethod
    def retrieve_entity(self, *args, **kwargs):
        """A hook method to retrieve an entity for processing.

        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: Entity instance to process in subsequent hook methods.
        """

    @abc.abstractmethod
    def handle_processing(self, entity, *args, **kwargs):
        """A hook method to handle processing on behalf of an entity.

        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: None if no follow on processing is needed for this task,
                 otherwise a :class:`FollowOnProcessingStatusDTO` instance
                 with information on how to process this task into the future.
        """

    @abc.abstractmethod
    def handle_error(self, entity, status, message, exception,
                     *args, **kwargs):
        """A hook method to deal with errors seen during processing.

        This method could be used to mark entity as being in error, and/or
        to record an error cause.

        :param entity: Entity retrieved from _retrieve_entity() above.
        :param status: Status code for exception.
        :param message: Reason/message for the exception.
        :param exception: Exception raised from handle_processing() above.
        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: None
        """

    @abc.abstractmethod
    def handle_success(self, entity, result, *args, **kwargs):
        """A hook method to post-process after successful entity processing.

        This method could be used to mark entity as being active, or to
        add information/references to the entity.

        :param entity: Entity retrieved from _retrieve_entity() above.
        :param result: A :class:`FollowOnProcessingStatusDTO` instance
                       representing processing result status, None implies
                       that no follow on processing is required.
        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: None
        """


class _OrderTaskHelper(object):
    """Supports order-related BaseTask operations.

    BaseTask sub-classes can delegate to an instance of this class to perform
    common order-related operations.
    """
    def __init__(self):
        self.order_repo = rep.get_order_repository()

    def retrieve_entity(self, order_id, external_project_id, *args, **kwargs):
        """Retrieve an order entity by its PK ID."""
        return self.order_repo.get(
            entity_id=order_id,
            external_project_id=external_project_id)

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        """Stamp the order entity as terminated due to an error."""
        order.status = models.States.ERROR
        order.error_status_code = status
        order.set_error_reason_safely(message)
        self.order_repo.save(order)

    def handle_success(self, order, result, *args, **kwargs):
        """Handle if the order entity is terminated or else long running.

        The 'result' argument (if present) indicates if a order should now be
        terminated due to it being completed, or else should be held in the
        PENDING state due to follow on workflow processing. If 'result' is not
        provided, the order is presumed completed.
        """
        is_follow_on_needed = False
        sub_status = None
        sub_status_message = None
        if result:
            is_follow_on_needed = result.is_follow_on_needed()
            sub_status = result.status
            sub_status_message = result.status_message

        if not is_follow_on_needed:
            order.status = models.States.ACTIVE
        else:
            order.status = models.States.PENDING

        if sub_status:
            order.set_sub_status_safely(sub_status)

        if sub_status_message:
            order.set_sub_status_message_safely(sub_status_message)

        self.order_repo.save(order)


class BeginTypeOrder(BaseTask):
    """Handles beginning processing of a TypeOrder."""

    def get_name(self):
        return u._('Process TypeOrder')

    def __init__(self):
        super(BeginTypeOrder, self).__init__()
        LOG.debug('Creating BeginTypeOrder task processor')
        self.project_repo = rep.get_project_repository()
        self.helper = _OrderTaskHelper()

    def retrieve_entity(self, *args, **kwargs):
        return self.helper.retrieve_entity(*args, **kwargs)

    def handle_processing(self, order, *args, **kwargs):
        return self.handle_order(order)

    def handle_order(self, order):
        """Handle secret creation using meta info.

        If type is key
            create secret
        if type is asymmetric
            create secrets
            create containers
        if type is certificate
            TBD
        :param order: Order to process.
        :return: None if no follow on processing is needed for this task,
                 otherwise a :class:`FollowOnProcessingStatusDTO` instance
                 with information on how to process this task into the future.
        """
        result_follow_on = common.FollowOnProcessingStatusDTO()

        order_info = order.to_dict_fields()
        order_type = order_info.get('type')
        meta_info = order_info.get('meta')
        if order_info.get('creator_id'):
            meta_info.setdefault('creator_id', order_info.get('creator_id'))

        # Retrieve the project.
        project = self.project_repo.get(order.project_id)

        if order_type == models.OrderType.KEY:
            # Create Secret
            new_secret = plugin.generate_secret(
                meta_info,
                meta_info.get('payload_content_type',
                              'application/octet-stream'),
                project
            )
            order.secret_id = new_secret.id
            LOG.debug("...done creating keys order's secret.")
        elif order_type == models.OrderType.ASYMMETRIC:
            # Create asymmetric Secret
            new_container = plugin.generate_asymmetric_secret(
                meta_info,
                meta_info.get('payload_content_type',
                              'application/octet-stream'),
                project)
            order.container_id = new_container.id
            LOG.debug("...done creating asymmetric order's secret.")
        elif order_type == models.OrderType.CERTIFICATE:
            # Request a certificate
            new_container = cert.issue_certificate_request(
                order, project, result_follow_on)
            if new_container:
                order.container_id = new_container.id
            LOG.debug("...done requesting a certificate.")
        else:
            raise NotImplementedError(
                u._('Order type "{order_type}" not implemented.').format(
                    order_type=order_type))

        return result_follow_on

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        self.helper.handle_error(
            order, status, message, exception, *args, **kwargs)

    def handle_success(self, order, result, *args, **kwargs):
        self.helper.handle_success(
            order, result, *args, **kwargs)


class UpdateOrder(BaseTask):
    """Handles updating an order."""
    def get_name(self):
        return u._('Update Order')

    def __init__(self):
        super(UpdateOrder, self).__init__()
        LOG.debug('Creating UpdateOrder task processor')
        self.helper = _OrderTaskHelper()

    def retrieve_entity(self, *args, **kwargs):
        return self.helper.retrieve_entity(*args, **kwargs)

    def handle_processing(
            self, order, order_id, external_project_id, updated_meta):
        self.handle_order(order, updated_meta)

    def handle_order(self, order, updated_meta):
        """Handle Order Update

        :param order: Order to update.
        """

        order_info = order.to_dict_fields()
        order_type = order_info.get('type')

        if order_type == models.OrderType.CERTIFICATE:
            # Update a certificate request
            cert.modify_certificate_request(order, updated_meta)
            LOG.debug("...done updating a certificate order.")
        else:
            raise NotImplementedError(
                u._('Order type "{order_type}" not implemented.').format(
                    order_type=order_type))

        LOG.debug("...done updating order.")

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        self.helper.handle_error(
            order, status, message, exception, *args, **kwargs)

    def handle_success(self, order, result, *args, **kwargs):
        self.helper.handle_success(
            order, result, *args, **kwargs)


class CheckCertificateStatusOrder(BaseTask):
    """Handles checking the status of a certificate order."""

    def get_name(self):
        return u._('Check Certificate Order Status')

    def __init__(self):
        LOG.debug('Creating CheckCertificateStatusOrder task processor')
        self.project_repo = rep.get_project_repository()
        self.helper = _OrderTaskHelper()

    def retrieve_entity(self, *args, **kwargs):
        return self.helper.retrieve_entity(*args, **kwargs)

    def handle_processing(self, order, *args, **kwargs):
        return self.handle_order(order)

    def handle_order(self, order):
        """Handle checking the status of a certificate order.

        :param order: Order to process.
        :return: None if no follow on processing is needed for this task,
                 otherwise a :class:`FollowOnProcessingStatusDTO` instance
                 with information on how to process this task into the future.
        """
        result_follow_on = common.FollowOnProcessingStatusDTO()

        order_info = order.to_dict_fields()
        order_type = order_info.get('type')

        # Retrieve the project.
        project = self.project_repo.get(order.project_id)

        if order_type != models.OrderType.CERTIFICATE:
            raise NotImplementedError(
                u._('Order type "{order_type}" not supported.').format(
                    order_type=order_type))

        # Request a certificate
        new_container = cert.check_certificate_request(
            order, project, result_follow_on)
        if new_container:
            order.container_id = new_container.id
        LOG.debug("...done checking status of a certificate order.")

        return result_follow_on

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        self.helper.handle_error(
            order, status, message, exception, *args, **kwargs)

    def handle_success(self, order, result, *args, **kwargs):
        self.helper.handle_success(
            order, result, *args, **kwargs)
