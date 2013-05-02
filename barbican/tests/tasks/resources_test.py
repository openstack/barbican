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

from mock import MagicMock
import json
import unittest

from datetime import datetime
from barbican.tasks.resources import BeginOrder
from barbican.model.models import Order, States
from barbican.model.repositories import OrderRepo
from barbican.common import config
from barbican.common import exception
from barbican.openstack.common import timeutils


def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenTestingVersionResource())

    return suite


class WhenBeginningOrder(unittest.TestCase):

    def setUp(self):
        self.requestor = 'requestor1234'
        self.order = Order()
        self.order.id = "id1"
        self.order.requestor = self.requestor
        
        self.secret_name = "name"
        self.secret_mime_type = "type"
        self.secret_expiration = timeutils.utcnow

        self.order.status = States.PENDING

        self.order_repo = MagicMock()
        self.order_repo.get.return_value = self.order

        self.resource = BeginOrder(self.order_repo)

    def test_should_process_order(self):
        self.resource.process(self.order.id)

        self.order_repo.get.assert_called_once_with(entity_id=self.order.id)
        assert self.order.status == States.ACTIVE


if __name__ == '__main__':
    unittest.main()
