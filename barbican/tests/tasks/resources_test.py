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

import unittest

from mock import MagicMock

from barbican.crypto.extension_manager import CryptoExtensionManager
from barbican.tasks.resources import BeginOrder
from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
from barbican.openstack.common import timeutils


def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenBeginningOrder())

    return suite


class WhenBeginningOrder(unittest.TestCase):

    def setUp(self):
        self.requestor = 'requestor1234'
        self.order = Order()
        self.order.id = "id1"
        self.order.requestor = self.requestor

        self.secret_name = "name"
        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_cypher_type = "CBC"
        self.secret_expiration = timeutils.utcnow()
        self.secret_payload_content_type = 'application/octet-stream'

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
        self.order.secret_algorithm = self.secret_algorithm
        self.order.secret_bit_length = self.secret_bit_length
        self.order.secret_cypher_type = self.secret_cypher_type
        self.order.secret_expiration = self.secret_expiration
        self.order.secret_payload_content_type = self\
            .secret_payload_content_type

        self.order_repo = MagicMock()
        self.order_repo.get.return_value = self.order

        self.secret_repo = MagicMock()
        self.secret_repo.create_from.return_value = None

        self.tenant_secret_repo = MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = MagicMock()

        self.conf = MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = CryptoExtensionManager(conf=self.conf)

        self.resource = BeginOrder(self.crypto_mgr,
                                   self.tenant_repo, self.order_repo,
                                   self.secret_repo, self.tenant_secret_repo,
                                   self.datum_repo, self.kek_repo)

    def test_should_process_order(self):
        self.resource.process(self.order.id, self.keystone_id)

        self.order_repo.get \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.keystone_id)
        self.assertEqual(self.order.status, States.ACTIVE)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertIsInstance(secret, Secret)
        self.assertEqual(secret.name, self.secret_name)
        self.assertEqual(secret.expiration, self.secret_expiration)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertIsInstance(tenant_secret, TenantSecret)
        self.assertEqual(tenant_secret.tenant_id, self.tenant_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, EncryptedDatum)
        self.assertIsNotNone(datum.cypher_text)

        self.assertIsNone(datum.kek_meta_extended)
        self.assertIsNotNone(datum.kek_meta_tenant)
        self.assertTrue(datum.kek_meta_tenant.bind_completed)
        self.assertIsNotNone(datum.kek_meta_tenant.plugin_name)
        self.assertIsNotNone(datum.kek_meta_tenant.kek_label)


if __name__ == '__main__':
    unittest.main()
