# Copyright (c) 2015 Rackspace, Inc.
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

from unittest import mock

from oslo_utils import timeutils

from barbican import i18n as u
from barbican.model import models
from barbican.tasks import common
from barbican.tasks import resources
from barbican.tests import utils


class BaseOrderTestCase(utils.BaseTestCase, utils.MockModelRepositoryMixin):

    def setUp(self):
        super(BaseOrderTestCase, self).setUp()
        self.requestor = 'requestor1234'
        self.order = models.Order()
        self.order.id = "id1"
        self.order.requestor = self.requestor
        self.order.type = "key"
        self.meta = {'name': 'name',
                     'payload_content_type':
                     'application/octet-stream',
                     'algorithm': 'AES',
                     'bit_length': 256,
                     'expiration': timeutils.utcnow(),
                     'mode': 'CBC'}
        self.order.meta = self.meta

        self.external_project_id = 'keystone1234'
        self.project_id = 'projectid1234'
        self.project = models.Project()
        self.project.id = self.project_id
        self.project.external_id = self.external_project_id
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        self.order.status = models.States.PENDING
        self.order.id = 'orderid1234'
        self.order.project_id = self.project_id
        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order
        self.setup_order_repository_mock(self.order_repo)

        self.setup_order_plugin_meta_repository_mock()
        self.setup_order_barbican_meta_repository_mock()

        self.secret = models.Secret()

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None
        self.setup_secret_repository_mock(self.secret_repo)

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None
        self.setup_encrypted_datum_repository_mock(self.datum_repo)

        self.setup_kek_datum_repository_mock()

        self.setup_secret_meta_repository_mock()

        self.container_repo = mock.MagicMock()
        self.container_repo.create_from.return_value = None
        self.setup_container_repository_mock(self.container_repo)

        self.container_secret_repo = mock.MagicMock()
        self.container_secret_repo.create_from.return_value = None
        self.setup_container_secret_repository_mock(self.container_secret_repo)

        self.container = models.Container()


class WhenUsingOrderTaskHelper(BaseOrderTestCase):

    def setUp(self):
        super(WhenUsingOrderTaskHelper, self).setUp()

        self.result = common.FollowOnProcessingStatusDTO()

        self.helper = resources._OrderTaskHelper()

    def test_should_retrieve_entity(self):
        order_model = self.helper.retrieve_entity(
            self.order.id, self.external_project_id)

        self.assertEqual(self.order.id, order_model.id)
        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

    def test_should_handle_error(self):
        self.helper.handle_error(self.order, 'status_code', 'reason',
                                 ValueError())

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual('status_code', self.order.error_status_code)
        self.assertEqual('reason', self.order.error_reason)
        self.order_repo.save.assert_called_once_with(self.order)

    def test_should_handle_success_no_result(self):
        self.helper.handle_success(self.order, None)

        self.assertEqual(models.States.ACTIVE, self.order.status)
        self.assertIsNone(self.order.sub_status)
        self.assertIsNone(self.order.sub_status_message)
        self.order_repo.save.assert_called_once_with(self.order)

    def test_should_handle_success_result_no_follow_on_needed(self):
        self.helper.handle_success(self.order, self.result)

        self.assertEqual(models.States.ACTIVE, self.order.status)
        self.assertEqual('Unknown', self.order.sub_status)
        self.assertEqual('Unknown', self.order.sub_status_message)
        self.order_repo.save.assert_called_once_with(self.order)

    def test_should_handle_success_result_follow_on_needed(self):
        self.result.retry_task = common.RetryTasks.INVOKE_SAME_TASK
        self.result.status = 'status'
        self.result.status_message = 'status_message'

        self.helper.handle_success(self.order, self.result)

        self.assertEqual(models.States.PENDING, self.order.status)
        self.assertEqual('status', self.order.sub_status)
        self.assertEqual('status_message', self.order.sub_status_message)
        self.order_repo.save.assert_called_once_with(self.order)

    def test_should_handle_success_result_large_statuses_clipped(self):
        sub_status = 'z' * (models.SUB_STATUS_LENGTH + 1)
        sub_status_message = 'z' * (models.SUB_STATUS_MESSAGE_LENGTH + 1)

        self.result.status = sub_status
        self.result.status_message = sub_status_message

        self.helper.handle_success(self.order, self.result)

        self.assertEqual(sub_status[:-1], self.order.sub_status)
        self.assertEqual(
            sub_status_message[:-1], self.order.sub_status_message)
        self.order_repo.save.assert_called_once_with(self.order)


class WhenBeginningKeyTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenBeginningKeyTypeOrder, self).setUp()

        self.resource = resources.BeginTypeOrder()

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_process_key_order(self, mock_generate_secret):
        mock_generate_secret.return_value = self.secret

        self.resource.process(self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)
        self.assertEqual(self.order.status, models.States.ACTIVE)

        secret_info = self.order.to_dict_fields()['meta']
        mock_generate_secret.assert_called_once_with(
            secret_info,
            secret_info.get('payload_content_type',
                            'application/octet-stream'),
            self.project
        )

    def test_should_fail_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_fail_during_processing(self):
        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Process TypeOrder failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_fail_during_success_report_fail(self,
                                                    mock_generate_secret):
        mock_generate_secret.return_value = self.secret
        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

    def test_should_fail_during_error_report_fail(self):
        # Force an error during the error-report handling after
        # error in processing handler phase.

        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
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
            self.external_project_id,
        )

        self.project_repo.get.assert_called_once_with(self.project_id)
        self.order_repo.save.assert_called_once_with(self.order)


class WhenBeginningCertificateTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenBeginningCertificateTypeOrder, self).setUp()

        self.order.type = models.OrderType.CERTIFICATE
        self.resource = resources.BeginTypeOrder()

    @mock.patch(
        'barbican.tasks.certificate_resources.issue_certificate_request')
    def test_should_process_order_no_container(
            self, mock_issue_cert_request):
        mock_issue_cert_request.return_value = None

        result = self.resource.process_and_suppress_exceptions(
            self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        mock_issue_cert_request.assert_called_once_with(
            self.order,
            self.project,
            mock.ANY
        )
        self.assertIsNone(self.order.container_id)
        self.assertIsInstance(result, common.FollowOnProcessingStatusDTO)

    @mock.patch(
        'barbican.tasks.certificate_resources.issue_certificate_request')
    def test_should_process_order_with_container(
            self, mock_issue_cert_request):
        mock_issue_cert_request.return_value = self.container

        result = self.resource.process(
            self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        mock_issue_cert_request.assert_called_once_with(
            self.order,
            self.project,
            mock.ANY
        )
        self.assertEqual(self.container.id, self.order.container_id)
        self.assertIsInstance(result, common.FollowOnProcessingStatusDTO)


class WhenUpdatingOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenUpdatingOrder, self).setUp()

        self.updated_meta = 'updated'

        self.resource = resources.UpdateOrder()

    @mock.patch(
        'barbican.tasks.certificate_resources.modify_certificate_request')
    def test_should_update_certificate_order(self, mock_modify_cert_request):
        self.order.type = models.OrderType.CERTIFICATE

        self.resource.process_and_suppress_exceptions(
            self.order.id, self.external_project_id, self.updated_meta)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        mock_modify_cert_request.assert_called_once_with(
            self.order,
            self.updated_meta
        )

    @mock.patch(
        'barbican.tasks.certificate_resources.modify_certificate_request')
    def test_should_fail_during_processing(self, mock_mod_cert):
        mock_mod_cert.side_effect = ValueError('Abort!')

        self.order.type = models.OrderType.CERTIFICATE

        exception = self.assertRaises(
            ValueError,
            self.resource.process,
            self.order_id,
            self.external_project_id,
            self.meta
        )

        self.assertEqual('Abort!', str(exception))

        mock_mod_cert.assert_called_once_with(self.order, self.meta)

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Update Order failure seen - please contact '
                             'site administrator.'), self.order.error_reason)


class WhenBeginningAsymmetricTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenBeginningAsymmetricTypeOrder, self).setUp()

        self.order.type = "asymmetric"

        self.resource = resources.BeginTypeOrder()

    @mock.patch('barbican.plugin.resources.generate_asymmetric_secret')
    def test_should_process_asymmetric_order(self,
                                             mock_generate_asymmetric_secret):
        mock_generate_asymmetric_secret.return_value = self.container
        self.resource.process(self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        secret_info = self.order.to_dict_fields()['meta']
        mock_generate_asymmetric_secret.assert_called_once_with(
            secret_info,
            secret_info.get('payload_content_type',
                            'application/octet-stream'),
            self.project
        )

    def test_should_fail_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_fail_during_processing(self):
        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Process TypeOrder failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    @mock.patch('barbican.plugin.resources.generate_asymmetric_secret')
    def test_should_fail_during_success_report_fail(self,
                                                    mock_generate_asym_secret):
        mock_generate_asym_secret.return_value = self.container
        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

    def test_should_fail_during_error_report_fail(self):
        # Force an error during the error-report handling after
        # error in processing handler phase.

        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
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
            self.external_project_id,
        )

        self.project_repo.get.assert_called_once_with(self.project_id)
        self.order_repo.save.assert_called_once_with(self.order)


class WhenCheckingCertificateStatus(BaseOrderTestCase):

    def setUp(self):
        super(WhenCheckingCertificateStatus, self).setUp()

        self.order.type = models.OrderType.CERTIFICATE

        self.resource = resources.CheckCertificateStatusOrder()

    @mock.patch(
        'barbican.tasks.certificate_resources.check_certificate_request')
    def test_should_process_order_no_container(
            self, mock_check_cert_request):
        mock_check_cert_request.return_value = None

        result = self.resource.process_and_suppress_exceptions(
            self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        mock_check_cert_request.assert_called_once_with(
            self.order,
            self.project,
            mock.ANY
        )
        self.assertIsNone(self.order.container_id)
        self.assertIsInstance(result, common.FollowOnProcessingStatusDTO)

    @mock.patch(
        'barbican.tasks.certificate_resources.check_certificate_request')
    def test_should_process_order_with_container(
            self, mock_check_cert_request):
        mock_check_cert_request.return_value = self.container

        self.resource.process(self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        mock_check_cert_request.assert_called_once_with(
            self.order,
            self.project,
            mock.ANY
        )
        self.assertEqual(self.container.id, self.order.container_id)

    def test_should_fail_with_bogus_order_type(self):
        self.order.type = 'bogus-type'

        self.assertRaises(
            NotImplementedError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        # Order state should be set to ERROR.
        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(
            ('Check Certificate Order Status failure seen - '
             'please contact site administrator.'),
            self.order.error_reason)
        self.assertEqual(500, self.order.error_status_code)
