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
from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
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
        self.secret_expiration = timeutils.utcnow()

        self.keystone_id = 'keystone1234'
        self.tenant_id = 'tenantid1234'
        self.tenant = Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.order.status = States.PENDING
        self.order.tenant_id = self.tenant_id
        self.order.secret_name = self.secret_name
        self.order.secret_expiration = self.secret_expiration
        self.order.secret_mime_type = self.secret_mime_type

        self.order_repo = MagicMock()
        self.order_repo.get.return_value = self.order

        self.secret_repo = MagicMock()
        self.secret_repo.create_from.return_value = None

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.resource = BeginOrder(self.tenant_repo, self.order_repo,
                                   self.secret_repo, self.tenant_secret_repo,
                                   self.datum_repo)

    def test_should_process_order(self):
        self.resource.process(self.order.id)

        self.order_repo.get.assert_called_once_with(entity_id=self.order.id)
        assert self.order.status == States.ACTIVE

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        assert isinstance(secret, Secret)
        assert secret.name == self.secret_name
        assert secret.expiration == self.secret_expiration

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        assert isinstance(tenant_secret, TenantSecret)
        assert tenant_secret.tenant_id == self.tenant_id
        assert tenant_secret.secret_id == secret.id

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        assert isinstance(datum, EncryptedDatum)
        assert self.secret_mime_type == datum.mime_type
        assert datum.cypher_text is not None
        assert datum.kek_metadata is not None


if __name__ == '__main__':
    unittest.main()
