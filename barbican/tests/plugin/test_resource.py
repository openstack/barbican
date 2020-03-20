# Copyright (c) 2014 Red Hat, Inc.
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
import base64
from unittest import mock

import testtools

from barbican.model import models
from barbican.plugin.interface import secret_store
from barbican.plugin import resources
from barbican.plugin import store_crypto
from barbican.tests import utils


@utils.parameterized_test_case
class WhenTestingPluginResource(testtools.TestCase,
                                utils.MockModelRepositoryMixin):

    def setUp(self):
        super(WhenTestingPluginResource, self).setUp()
        self.plugin_resource = resources
        self.spec = {'algorithm': 'RSA',
                     'bit_length': 1024,
                     'passphrase': 'changeit'
                     }
        self.content_type = 'application/octet-stream'
        self.project_model = mock.MagicMock()
        asymmetric_meta_dto = secret_store.AsymmetricKeyMetadataDTO()
        # Mock plug-in
        self.moc_plugin = mock.MagicMock()
        self.moc_plugin.generate_asymmetric_key.return_value = (
            asymmetric_meta_dto)
        self.moc_plugin.store_secret.return_value = {}

        moc_plugin_config = {
            'return_value.get_plugin_generate.return_value':
            self.moc_plugin,
            'return_value.get_plugin_store.return_value':
            self.moc_plugin,
            'return_value.get_plugin_retrieve_delete.return_value':
            self.moc_plugin
        }

        self.moc_plugin_patcher = mock.patch(
            'barbican.plugin.interface.secret_store.get_manager',
            **moc_plugin_config
        )
        self.moc_plugin_manager = self.moc_plugin_patcher.start()
        self.addCleanup(self.moc_plugin_patcher.stop)

        self.setup_project_repository_mock()

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None
        self.setup_secret_repository_mock(self.secret_repo)

        self.container_repo = mock.MagicMock()
        self.container_repo.create_from.return_value = None
        self.setup_container_repository_mock(self.container_repo)

        self.container_secret_repo = mock.MagicMock()
        self.container_secret_repo.create_from.return_value = None
        self.setup_container_secret_repository_mock(
            self.container_secret_repo)

        self.secret_meta_repo = mock.MagicMock()
        self.secret_meta_repo.create_from.return_value = None
        self.setup_secret_meta_repository_mock(self.secret_meta_repo)

    def tearDown(self):
        super(WhenTestingPluginResource, self).tearDown()

    def test_store_secret_dto(self):
        spec = {'algorithm': 'AES', 'bit_length': 256,
                'secret_type': 'symmetric'}
        secret = base64.b64encode(b'ABCDEFABCDEFABCDEFABCDEF')

        self.plugin_resource.store_secret(
            unencrypted_raw=secret,
            content_type_raw=self.content_type,
            content_encoding='base64',
            secret_model=models.Secret(spec),
            project_model=self.project_model)

        dto = self.moc_plugin.store_secret.call_args_list[0][0][0]
        self.assertEqual("symmetric", dto.type)
        self.assertEqual(secret, dto.secret)
        self.assertEqual(spec['algorithm'], dto.key_spec.alg)
        self.assertEqual(spec['bit_length'], dto.key_spec.bit_length)
        self.assertEqual(self.content_type, dto.content_type)

    @utils.parameterized_dataset({
        'general_secret_store': {
            'moc_plugin': None
        },
        'store_crypto': {
            'moc_plugin': mock.MagicMock(store_crypto.StoreCryptoAdapterPlugin)
        }
    })
    def test_get_secret_dto(self, moc_plugin):

        def mock_secret_store_store_secret(dto):
            self.secret_dto = dto

        def mock_secret_store_get_secret(secret_type, secret_metadata):
            return self.secret_dto

        def mock_store_crypto_store_secret(dto, context):
            self.secret_dto = dto

        def mock_store_crypto_get_secret(
                secret_type, secret_metadata, context):
            return self.secret_dto

        if moc_plugin:
            self.moc_plugin = moc_plugin
            self.moc_plugin.store_secret.return_value = {}
            self.moc_plugin.store_secret.side_effect = (
                mock_store_crypto_store_secret)
            self.moc_plugin.get_secret.side_effect = (
                mock_store_crypto_get_secret)

            moc_plugin_config = {
                'return_value.get_plugin_store.return_value':
                self.moc_plugin,
                'return_value.get_plugin_retrieve_delete.return_value':
                self.moc_plugin
            }
            self.moc_plugin_manager.configure_mock(**moc_plugin_config)
        else:
            self.moc_plugin.store_secret.side_effect = (
                mock_secret_store_store_secret)
            self.moc_plugin.get_secret.side_effect = (
                mock_secret_store_get_secret)

        raw_secret = b'ABCDEFABCDEFABCDEFABCDEF'
        spec = {'name': 'testsecret', 'algorithm': 'AES', 'bit_length': 256,
                'secret_type': 'symmetric'}

        self.plugin_resource.store_secret(
            unencrypted_raw=base64.b64encode(raw_secret),
            content_type_raw=self.content_type,
            content_encoding='base64',
            secret_model=models.Secret(spec),
            project_model=self.project_model)

        secret = self.plugin_resource.get_secret(
            'application/octet-stream',
            models.Secret(spec),
            None)
        self.assertEqual(raw_secret, secret)

    def test_generate_asymmetric_with_passphrase(self):
        """test asymmetric secret generation with passphrase."""
        secret_container = self.plugin_resource.generate_asymmetric_secret(
            self.spec,
            self.content_type,
            self.project_model,
        )

        self.assertEqual("rsa", secret_container.type)
        self.assertEqual(self.moc_plugin.
                         generate_asymmetric_key.call_count, 1)
        self.assertEqual(self.container_repo.
                         create_from.call_count, 1)
        self.assertEqual(self.container_secret_repo.
                         create_from.call_count, 3)

    def test_generate_asymmetric_without_passphrase(self):
        """test asymmetric secret generation without passphrase."""

        del self.spec['passphrase']
        secret_container = self.plugin_resource.generate_asymmetric_secret(
            self.spec,
            self.content_type,
            self.project_model,
        )

        self.assertEqual("rsa", secret_container.type)
        self.assertEqual(1,
                         self.moc_plugin.generate_asymmetric_key.call_count)
        self.assertEqual(1, self.container_repo.create_from.call_count)
        self.assertEqual(2, self.container_secret_repo.create_from.call_count)

    def test_delete_secret_w_metadata(self):
        project_id = "some_id"
        secret_model = mock.MagicMock()
        secret_meta = mock.MagicMock()
        self.secret_meta_repo.get_metadata_for_secret.return_value = (
            secret_meta)
        self.plugin_resource.delete_secret(secret_model=secret_model,
                                           project_id=project_id)

        self.secret_meta_repo.get_metadata_for_secret.assert_called_once_with(
            secret_model.id)

        self.moc_plugin.delete_secret.assert_called_once_with(secret_meta)

        self.secret_repo.delete_entity_by_id.assert_called_once_with(
            entity_id=secret_model.id, external_project_id=project_id)

    def test_delete_secret_w_out_metadata(self):
        project_id = "some_id"
        secret_model = mock.MagicMock()
        self.secret_meta_repo.get_metadata_for_secret.return_value = None
        self.plugin_resource.delete_secret(secret_model=secret_model,
                                           project_id=project_id)

        self.secret_meta_repo.get_metadata_for_secret.assert_called_once_with(
            secret_model.id)

        self.secret_repo.delete_entity_by_id.assert_called_once_with(
            entity_id=secret_model.id, external_project_id=project_id)
