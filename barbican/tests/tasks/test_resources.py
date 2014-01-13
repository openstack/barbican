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

import unittest

import falcon
import mock

from barbican.crypto import extension_manager as em
from barbican.model import models
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import timeutils
from barbican.tasks import resources


class WhenBeginningOrder(unittest.TestCase):

    def setUp(self):
        self.requestor = 'requestor1234'
        self.order = models.Order()
        self.order.id = "id1"
        self.order.requestor = self.requestor

        self.secret_name = "name"
        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"
        self.secret_expiration = timeutils.utcnow()
        self.secret_payload_content_type = 'application/octet-stream'

        self.keystone_id = 'keystone1234'
        self.tenant_id = 'tenantid1234'
        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.order.status = models.States.PENDING
        self.order.tenant_id = self.tenant_id
        self.order.secret_name = self.secret_name
        self.order.secret_algorithm = self.secret_algorithm
        self.order.secret_bit_length = self.secret_bit_length
        self.order.secret_mode = self.secret_mode
        self.order.secret_expiration = self.secret_expiration
        self.order.secret_payload_content_type = self\
            .secret_payload_content_type

        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None

        self.tenant_secret_repo = mock.MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.conf = mock.MagicMock()
        self.conf.crypto.namespace = 'barbican.test.crypto.plugin'
        self.conf.crypto.enabled_crypto_plugins = ['test_crypto']
        self.crypto_mgr = em.CryptoExtensionManager(conf=self.conf)

        self.resource = resources.BeginOrder(self.crypto_mgr,
                                             self.tenant_repo, self.order_repo,
                                             self.secret_repo,
                                             self.tenant_secret_repo,
                                             self.datum_repo, self.kek_repo)

    def test_should_process_order(self):
        self.resource.process(self.order.id, self.keystone_id)

        self.order_repo.get \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.keystone_id)
        self.assertEqual(self.order.status, models.States.ACTIVE)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        self.assertIsInstance(secret, models.Secret)
        self.assertEqual(secret.name, self.secret_name)
        self.assertEqual(secret.expiration, self.secret_expiration)

        args, kwargs = self.tenant_secret_repo.create_from.call_args
        tenant_secret = args[0]
        self.assertIsInstance(tenant_secret, models.TenantSecret)
        self.assertEqual(tenant_secret.tenant_id, self.tenant_id)
        self.assertEqual(tenant_secret.secret_id, secret.id)

        args, kwargs = self.datum_repo.create_from.call_args
        datum = args[0]
        self.assertIsInstance(datum, models.EncryptedDatum)
        self.assertIsNotNone(datum.cypher_text)

        self.assertIsNone(datum.kek_meta_extended)
        self.assertIsNotNone(datum.kek_meta_tenant)
        self.assertTrue(datum.kek_meta_tenant.bind_completed)
        self.assertIsNotNone(datum.kek_meta_tenant.plugin_name)
        self.assertIsNotNone(datum.kek_meta_tenant.kek_label)

    def test_should_fail_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        with self.assertRaises(ValueError):
            self.resource.process(self.order.id, self.keystone_id)

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_fail_during_processing(self):
        # Force an error during the processing handler phase.
        self.tenant_repo.get = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        with self.assertRaises(ValueError):
            self.resource.process(self.order.id, self.keystone_id)

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(falcon.HTTP_500, self.order.error_status_code)
        self.assertEqual(u._('Create Secret failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    def test_should_fail_during_success_report_fail(self):
        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        with self.assertRaises(ValueError):
            self.resource.process(self.order.id, self.keystone_id)

    def test_should_fail_during_error_report_fail(self):
        # Force an error during the error-report handling after
        # error in processing handler phase.

        # Force an error during the processing handler phase.
        self.tenant_repo.get = mock.MagicMock(return_value=None,
                                              side_effect=TypeError())

        # Force exception in the error-reporting phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        # Should see the original exception (TypeError) instead of the
        # secondary one (ValueError).
        with self.assertRaises(TypeError):
            self.resource.process(self.order.id, self.keystone_id)


class WhenPerformingVerification(unittest.TestCase):

    def setUp(self):
        self.verif = models.Verification()
        self.verif.id = "id1"

        self.resource_type = 'image',
        self.resource_ref = 'http://www.images.com/images/123',
        self.resource_action = 'vm_attach',
        self.impersonation_allowed = True

        self.keystone_id = 'keystone1234'
        self.tenant_id = 'tenantid1234'
        self.tenant = models.Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.keystone_id = self.keystone_id
        self.tenant_repo = mock.MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.verif.status = models.States.PENDING
        self.verif.tenant_id = self.tenant_id
        self.verif.resource_type = self.resource_type
        self.verif.resource_ref = self.resource_ref
        self.verif.resource_action = self.resource_action
        self.verif.impersonation_allowed = self.impersonation_allowed

        self.verif_repo = mock.MagicMock()
        self.verif_repo.get.return_value = self.verif

        self.resource = resources.PerformVerification(self.verif_repo)

    def test_should_process_verification(self):
        self.resource.process(self.verif.id, self.keystone_id)

        self.verif_repo.get \
            .assert_called_once_with(entity_id=self.verif.id,
                                     keystone_id=self.keystone_id)
        self.assertEqual(self.verif.status, models.States.ACTIVE)

        args, kwargs = self.verif_repo.save.call_args
        verif = args[0]
        self.assertIsInstance(verif, models.Verification)
        self.assertEqual(verif.resource_type, self.resource_type)
        self.assertEqual(verif.resource_action, self.resource_action)

    def test_should_fail_during_retrieval(self):
        # Force an error during the verification retrieval phase.
        self.verif_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        with self.assertRaises(ValueError):
            self.resource.process(self.verif.id, self.keystone_id)

        # Verification state doesn't change because can't retrieve
        #   it to change it.
        self.assertEqual(models.States.PENDING, self.verif.status)

    def test_should_fail_during_success_report_fail(self):
        # Force an error during the processing handler phase.
        self.verif_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        with self.assertRaises(ValueError):
            self.resource.process(self.verif.id, self.keystone_id)
