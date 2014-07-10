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

import mock
import testtools

from barbican.model import models
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import timeutils
from barbican.tasks import resources


class WhenBeginningOrder(testtools.TestCase):

    def setUp(self):
        super(WhenBeginningOrder, self).setUp()

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

        self.secret = models.Secret()

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None

        self.tenant_secret_repo = mock.MagicMock()
        self.tenant_secret_repo.create_from.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.secret_meta_repo = mock.MagicMock()

        self.resource = resources.BeginOrder(self.tenant_repo, self.order_repo,
                                             self.secret_repo,
                                             self.tenant_secret_repo,
                                             self.datum_repo, self.kek_repo,
                                             self.secret_meta_repo
                                             )

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_process_order(self, mock_generate_secret):
        mock_generate_secret.return_value = self.secret

        self.resource.process(self.order.id, self.keystone_id)

        self.order_repo.get \
            .assert_called_once_with(entity_id=self.order.id,
                                     keystone_id=self.keystone_id)
        self.assertEqual(self.order.status, models.States.ACTIVE)

        secret_info = self.order.to_dict_fields()['secret']
        mock_generate_secret\
            .assert_called_once_with(
                secret_info,
                secret_info.get('payload_content_type',
                                'application/octet-stream'),
                self.tenant, mock.ANY
            )

    def test_should_raise_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.keystone_id,
        )

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_raise_during_processing(self):
        # Force an error during the processing handler phase.
        self.tenant_repo.get = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.keystone_id,
        )

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Create Secret failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_raise_during_success_report_fail(self,
                                                     mock_generate_secret):
        mock_generate_secret.return_value = self.secret

        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.keystone_id,
        )

    def test_should_raise_during_error_report_fail(self):
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
        self.assertRaises(
            TypeError,
            self.resource.process,
            self.order.id,
            self.keystone_id,
        )
