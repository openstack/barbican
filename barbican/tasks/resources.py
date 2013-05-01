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

from barbican.model.repositories import OrderRepo
from barbican.model.models import States
from barbican.common import utils

LOG = utils.getLogger(__name__)


class BeginOrder(object):
    """Handles beginning processing an Order"""

    def __init__(self, order_repo=None):
        self.repo = order_repo or OrderRepo()

    def process(self, order_id):
        """Process the beginning of an Order."""
        LOG.debug("Processing Order with ID = {0}".format(order_id))

        # Retrieve the order.
        order = self.repo.get(entity_id=order_id)
        self._handle_order(order)

        # Indicate we are done with Order processing
        order.status = States.ACTIVE
        self.repo.save(order)

        return None

    def _handle_order(self, order):
        LOG.debug("Handling order for secret type of {0}...".format(order.secret_mime_type))
        sleep(20.0)
        
        LOG.debug("...done creating order's secret.")
