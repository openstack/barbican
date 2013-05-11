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
Task resources for the Barbican API.
"""
from time import sleep

from barbican.model.repositories import (OrderRepo, TenantRepo, SecretRepo,
                                         TenantSecretRepo, EncryptedDatumRepo)
from barbican.model.models import States
from barbican.common.resources import create_secret
from barbican.common import utils

LOG = utils.getLogger(__name__)


class BeginOrder(object):
    """Handles beginning processing an Order"""

    def __init__(self, tenant_repo=None, order_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None):
        LOG.debug('Creating BeginOrder task processor')
        self.order_repo = order_repo or OrderRepo()
        self.tenant_repo = tenant_repo or TenantRepo()
        self.secret_repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()

    def process(self, order_id):
        """Process the beginning of an Order."""
        LOG.debug("Processing Order with ID = {0}".format(order_id))

        # Retrieve the order.
        order = self.order_repo.get(entity_id=order_id)
        self._handle_order(order)

        # Indicate we are done with Order processing
        order.status = States.ACTIVE
        self.order_repo.save(order)

        return None

    def _handle_order(self, order):
        """
        Either creates a secret item here, or else begins the extended
        process of creating a secret (such as for SSL certificate
        generation.
        """
        LOG.debug("Handling order for secret type of {0}..."
                  .format(order.secret_mime_type))

        order_info = order.to_dict_fields()
        secret_info = order_info['secret']

        # Create Secret
        new_secret = create_secret(secret_info, order.tenant_id,
                                   self.tenant_repo, self.secret_repo,
                                   self.tenant_secret_repo, self.datum_repo,
                                   ok_to_generate=True)
        order.secret_id = new_secret.id

        LOG.debug("...done creating order's secret.")
