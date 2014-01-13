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

from barbican import api
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import verifications as ver
from barbican.crypto import extension_manager as em
from barbican.model import models
from barbican.model import repositories as rep
from barbican.openstack.common import gettextutils as u

LOG = utils.getLogger(__name__)


class BaseTask(object):
    """Base asychronous task."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_name(self):
        """A hook method to return a short localized name for this task.
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
                              "process task '{0}'.").format(name))
            raise e

        # Process the target entity.
        try:
            self.handle_processing(entity, *args, **kwargs)
        except Exception as e_orig:
            LOG.exception(u._("Could not perform processing for "
                              "task '{0}'.").format(name))

            # Handle failure to process entity.
            try:
                status, message = api \
                    .generate_safe_exception_message(name, e_orig)
                self.handle_error(entity, status, message, e_orig,
                                  *args, **kwargs)
            except Exception:
                LOG.exception(u._("Problem handling an error for task '{0}', "
                                  "raising original "
                                  "exception.").format(name))
            raise e_orig

        # Handle successful conclusion of processing.
        try:
            self.handle_success(entity, *args, **kwargs)
        except Exception as e:
            LOG.exception(u._("Could not process after successfully executing"
                              " task '{0}'.").format(name))
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


class BeginOrder(BaseTask):
    """Handles beginning processing an Order"""

    def get_name(self):
        return u._('Create Secret')

    def __init__(self, crypto_manager=None, tenant_repo=None, order_repo=None,
                 secret_repo=None, tenant_secret_repo=None,
                 datum_repo=None, kek_repo=None):
        LOG.debug('Creating BeginOrder task processor')
        self.order_repo = order_repo or rep.OrderRepo()
        self.tenant_repo = tenant_repo or rep.TenantRepo()
        self.secret_repo = secret_repo or rep.SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or rep.TenantSecretRepo()
        self.datum_repo = datum_repo or rep.EncryptedDatumRepo()
        self.kek_repo = kek_repo or rep.KEKDatumRepo()
        self.crypto_manager = crypto_manager or em.CryptoExtensionManager()

    def retrieve_entity(self, order_id, keystone_id):
        return self.order_repo.get(entity_id=order_id,
                                   keystone_id=keystone_id)

    def handle_processing(self, order, *args, **kwargs):
        self.handle_order(order)

    def handle_error(self, order, status, message, exception,
                     *args, **kwargs):
        order.status = models.States.ERROR
        order.error_status_code = status
        order.error_reason = message
        self.order_repo.save(order)

    def handle_success(self, order, *args, **kwargs):
        order.status = models.States.ACTIVE
        self.order_repo.save(order)

    def handle_order(self, order):
        """Handle secret creation.

        Either creates a secret item here, or else begins the extended
        process of creating a secret (such as for SSL certificate
        generation.

        :param order: Order to process on behalf of.
        """
        order_info = order.to_dict_fields()
        secret_info = order_info['secret']

        # Retrieve the tenant.
        tenant = self.tenant_repo.get(order.tenant_id)

        # Create Secret
        new_secret = res.create_secret(secret_info, tenant,
                                       self.crypto_manager, self.secret_repo,
                                       self.tenant_secret_repo,
                                       self.datum_repo, self.kek_repo,
                                       ok_to_generate=True)
        order.secret_id = new_secret.id

        LOG.debug("...done creating order's secret.")


class PerformVerification(BaseTask):
    """Handles beginning processing a Verification request."""

    def get_name(self):
        return u._('Perform Verification')

    def __init__(self, verification_repo=None):
        LOG.debug('Creating PerformVerification task processor')
        self.verification_repo = verification_repo or rep.VerificationRepo()

    def retrieve_entity(self, verification_id, keystone_id):
        return self.verification_repo.get(entity_id=verification_id,
                                          keystone_id=keystone_id)

    def handle_processing(self, verification, *args, **kwargs):
        self.handle_verification(verification)

    def handle_error(self, verification, status, message, exception,
                     *args, **kwargs):
        verification.status = models.States.ERROR
        verification.error_status_code = status
        verification.error_reason = message
        self.verification_repo.save(verification)

    def handle_success(self, verification, *args, **kwargs):
        verification.status = models.States.ACTIVE
        self.verification_repo.save(verification)

    def handle_verification(self, verification):
        """Handle performing a verification.

        Performs a verification process on a reference.

        :param verification: Verification to process on behalf of.
        """
        # Perform the verification.
        ver.verify(verification)

        LOG.debug("...done verifying resource.")
