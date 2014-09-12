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
Task resources for the Barbican API.
"""
import abc

import six

from barbican import api
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories as rep
from barbican.openstack.common import gettextutils as u
from barbican.plugin import resources as plugin
from barbican.tasks import certificate_resources as cert


LOG = utils.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseTask(object):
    """Base asynchronous task."""

    @abc.abstractmethod
    def get_name(self):
        """Localized task name

        A hook method to return a short localized name for this task.
        The returned name in the form 'u.('Verb Noun')'. For example:
            u._('Create Secret')
        """

    def process(self, *args, **kwargs):
        """A template method for all asynchronous tasks.

        This method should not be overridden by sub-classes. Rather the
        abstract methods below should be overridden.

        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: None
        """
        name = self.get_name()

        # Retrieve the target entity (such as an models.Order instance).
        try:
            entity = self.retrieve_entity(*args, **kwargs)
        except Exception as e:
            # Serious error!
            LOG.exception(u._("Could not retrieve information needed to "
                              "process task '%s'."), name)
            raise e

        # Process the target entity.
        try:
            self.handle_processing(entity, *args, **kwargs)
        except Exception as e_orig:
            LOG.exception(u._("Could not perform processing for "
                              "task '%s'."), name)

            # Handle failure to process entity.
            try:
                status, message = api.generate_safe_exception_message(name,
                                                                      e_orig)
                self.handle_error(entity, status, message, e_orig,
                                  *args, **kwargs)
            except Exception:
                LOG.exception(u._("Problem handling an error for task '%s', "
                                  "raising original "
                                  "exception."), name)
            raise e_orig

        # Handle successful conclusion of processing.
        try:
            self.handle_success(entity, *args, **kwargs)
        except Exception as e:
            LOG.exception(u._("Could not process after successfully executing"
                              " task '%s'."), name)
            raise e

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
        :return: None
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
    def handle_success(self, entity, *args, **kwargs):
        """A hook method to post-process after successful entity processing.

        This method could be used to mark entity as being active, or to
        add information/references to the entity.

        :param entity: Entity retrieved from _retrieve_entity() above.
        :param args: List of arguments passed in from the client.
        :param kwargs: Dict of arguments passed in from the client.
        :return: None
        """


class BeginTypeOrder(BaseTask):
    """Handles beginning processing of a TypeOrder."""

    def get_name(self):
        return u._('Process TypeOrder')

    def __init__(self, tenant_repo=None, order_repo=None,
                 secret_repo=None, tenant_secret_repo=None, datum_repo=None,
                 kek_repo=None, container_repo=None,
                 container_secret_repo=None, secret_meta_repo=None,
                 order_plugin_meta_repo=None):
            LOG.debug('Creating BeginTypeOrder task processor')
            self.repos = rep.Repositories(
                tenant_repo=tenant_repo,
                tenant_secret_repo=tenant_secret_repo,
                secret_repo=secret_repo,
                datum_repo=datum_repo,
                kek_repo=kek_repo,
                secret_meta_repo=secret_meta_repo,
                order_repo=order_repo,
                order_plugin_meta_repo=order_plugin_meta_repo,
                container_repo=container_repo,
                container_secret_repo=container_secret_repo)

    def retrieve_entity(self, order_id, keystone_id):
        return self.repos.order_repo.get(entity_id=order_id,
                                         keystone_id=keystone_id)

    def handle_processing(self, order, *args, **kwargs):
        self.handle_order(order)

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        order.status = models.States.ERROR
        order.error_status_code = status
        order.error_reason = message
        self.repos.order_repo.save(order)

    def handle_success(self, order, *args, **kwargs):
        if models.OrderType.CERTIFICATE != order.type:
            order.status = models.States.ACTIVE
        else:
            # TODO(alee-3): enable the code below when sub status is added
            # if cert.ORDER_STATUS_CERT_GENERATED.id == order.sub_status:
            #    order.status = models.States.ACTIVE
            order.status = models.States.ACTIVE

        self.repos.order_repo.save(order)

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
        """
        order_info = order.to_dict_fields()
        order_type = order_info.get('type')
        meta_info = order_info.get('meta')

        # Retrieve the tenant.
        tenant = self.repos.tenant_repo.get(order.tenant_id)

        if order_type == models.OrderType.KEY:
            # Create Secret
            new_secret = plugin.generate_secret(
                meta_info,
                meta_info.get('payload_content_type',
                              'application/octet-stream'),
                tenant,
                self.repos
            )
            order.secret_id = new_secret.id
            LOG.debug("...done creating keys order's secret.")
        elif order_type == models.OrderType.ASYMMETRIC:
            # Create asymmetric Secret
            new_container = plugin.generate_asymmetric_secret(
                meta_info,
                meta_info.get('payload_content_type',
                              'application/octet-stream'),
                tenant, self.repos)
            order.container_id = new_container.id
            LOG.debug("...done creating asymmetric order's secret.")
        elif order_type == models.OrderType.CERTIFICATE:
            # Request a certificate
            new_container = cert.issue_certificate_request(
                order, tenant, self.repos)
            if new_container:
                order.container_id = new_container.id
            LOG.debug("...done requesting a certificate.")
        else:
            raise NotImplementedError(
                'Order type "{0}" not implemented.'.format(order_type))


class UpdateOrder(BaseTask):
    """Handles updating an order."""
    def get_name(self):
        return u._('Update Order')

    def __init__(self, tenant_repo=None, order_repo=None,
                 secret_repo=None, tenant_secret_repo=None, datum_repo=None,
                 kek_repo=None, container_repo=None,
                 container_secret_repo=None, secret_meta_repo=None):
            LOG.debug('Creating UpdateOrder task processor')
            self.repos = rep.Repositories(
                tenant_repo=tenant_repo,
                order_repo=order_repo,
                secret_repo=secret_repo,
                tenant_secret_repo=tenant_secret_repo,
                datum_repo=datum_repo,
                kek_repo=kek_repo,
                container_repo=container_repo,
                container_secret_repo=container_secret_repo,
                secret_meta_repo=secret_meta_repo
            )

    def retrieve_entity(self, order_id, keystone_id):
        return self.repos.order_repo.get(entity_id=order_id,
                                         keystone_id=keystone_id)

    def handle_processing(self, order, updated_meta):
        self.handle_order(order, updated_meta)

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        order.status = models.States.ERROR
        order.error_status_code = status
        order.error_reason = message
        LOG.exception(u._("An error has occurred updating the order."))
        self.repos.order_repo.save(order)

    def handle_success(self, order, *args, **kwargs):
        # TODO(chellygel): Handle sub-status on a pending order.
        order.status = models.States.ACTIVE
        self.repos.order_repo.save(order)

    def handle_order(self, order, updated_meta):
        """Handle Order Update

        :param order: Order to update.
        """

        order_info = order.to_dict_fields()
        order_type = order_info.get('type')

        if order_type == models.OrderType.CERTIFICATE:
            # Update a certificate request
            cert.modify_certificate_request(order, updated_meta, self.repos)
            LOG.debug("...done updating a certificate order.")
        else:
            raise NotImplementedError(
                'Order type "{0}" not implemented.'.format(order_type))

        LOG.debug("...done updating order.")
