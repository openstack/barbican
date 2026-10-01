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

from sqlalchemy import exc as sa_exc
import testtools

from barbican.common import exception
from barbican.model import models
from barbican.plugin.crypto import base as crypto_base
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

    def _make_secret_store(self, store_plugin='kmip_plugin',
                           crypto_plugin=None):
        secret_store_model = mock.MagicMock()
        secret_store_model.id = 'ss-1'
        secret_store_model.store_plugin = store_plugin
        secret_store_model.crypto_plugin = crypto_plugin
        return secret_store_model

    def _make_secret(self, encrypted_data=None, secret_id='sid'):
        secret_model = mock.MagicMock()
        secret_model.id = secret_id
        secret_model.encrypted_data = encrypted_data or []
        secret_model.secret_store_metadata = {}
        self.secret_repo.get_secret_by_id.return_value = secret_model
        return secret_model

    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_already_on_target_is_noop(self, mock_fullname):
        mock_fullname.return_value = 'plugin.Full.Name'
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'plugin.Full.Name',
            'content_type': 'application/octet-stream',
        }
        secret_model = self._make_secret()

        resources.rewrap_secret(
            secret_model, self.project_model, self._make_secret_store())

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            'sid', for_update=True)
        self.moc_plugin.store_secret.assert_not_called()
        self.moc_plugin.delete_secret.assert_not_called()

    def test_rewrap_secret_without_payload_raises(self):
        self.secret_meta_repo.get_metadata_for_secret.return_value = {}
        secret_model = self._make_secret()

        self.assertRaises(
            exception.SecretPayloadNotFound,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store())

    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_concurrent_second_migrate_is_noop(
            self, mock_fullname):
        """After FOR UPDATE, a finished peer migrate makes this a no-op."""
        mock_fullname.return_value = 'NewPlugin'
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        # Locked row already reflects the destination plugin.
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'already-moved',
        }
        secret_model = self._make_secret()

        resources.rewrap_secret(
            secret_model, self.project_model, self._make_secret_store())

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            'sid', for_update=True)
        self.moc_plugin.store_secret.assert_not_called()
        self.moc_plugin.delete_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_raises_when_decrypt_fails(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        mock_get.side_effect = RuntimeError('decrypt failed')
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        }
        secret_model = self._make_secret()

        self.assertRaises(
            RuntimeError,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store())

        self.moc_plugin.store_secret.assert_not_called()
        self.moc_plugin.delete_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_raises_when_store_plugin_fails(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.side_effect = (
            exception.BarbicanException('store plugin failed'))
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        }
        secret_model = self._make_secret()

        self.assertRaises(
            exception.BarbicanException,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store())

        self.moc_plugin.store_secret.assert_called_once()
        # Nothing was stored successfully, so no rollback delete and
        # the source plugin object must remain.
        self.moc_plugin.delete_secret.assert_not_called()
        self.secret_meta_repo.delete_for_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_stores_then_deletes_old_object(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {'secret_id': 'new-obj'}
        old_meta = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        }
        new_meta = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'new-obj',
        }
        # already-on-target check, current_meta, then saved_meta
        self.secret_meta_repo.get_metadata_for_secret.side_effect = [
            old_meta, old_meta, new_meta,
        ]
        old_datum = mock.MagicMock()
        old_datum.id = 'd1'
        old_datum.deleted = False
        secret_model = self._make_secret(encrypted_data=[old_datum])

        resources.rewrap_secret(
            secret_model, self.project_model, self._make_secret_store())

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            'sid', for_update=True)
        self.moc_plugin.store_secret.assert_called_once()
        self.secret_meta_repo.delete_for_secret.assert_called_once_with('sid')
        old_datum.delete.assert_called_once()
        self.moc_plugin.delete_secret.assert_called_once_with({
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        })

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_skips_delete_when_object_identity_matches(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = None
        old_meta = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
        }
        new_meta = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
        }
        self.secret_meta_repo.get_metadata_for_secret.side_effect = [
            old_meta, old_meta, new_meta,
        ]
        old_datum = mock.MagicMock()
        old_datum.id = 'd1'
        old_datum.deleted = False
        secret_model = self._make_secret(encrypted_data=[old_datum])

        resources.rewrap_secret(
            secret_model, self.project_model, self._make_secret_store())

        self.moc_plugin.store_secret.assert_called_once()
        self.moc_plugin.delete_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_rolls_back_new_object_on_failure(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {'secret_id': 'new-obj'}
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        }
        self.secret_meta_repo.save.side_effect = sa_exc.SQLAlchemyError(
            'db fail')
        secret_model = self._make_secret()

        self.assertRaises(
            sa_exc.SQLAlchemyError,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store())

        self.moc_plugin.delete_secret.assert_called_once_with(
            {'secret_id': 'new-obj'})

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_does_not_rollback_unexpected_errors(
            self, mock_fullname, mock_get):
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {'secret_id': 'new-obj'}
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'old-obj',
        }
        self.secret_meta_repo.save.side_effect = RuntimeError('unexpected')
        secret_model = self._make_secret()

        self.assertRaises(
            RuntimeError,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store())

        self.moc_plugin.delete_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources.crypto_mgr.get_manager',
                autospec=True)
    def test_rewrap_secret_raises_crypto_plugin_not_found(
            self, mock_crypto_mgr):
        mock_crypto_mgr.return_value.get_plugin_by_name.side_effect = (
            crypto_base.CryptoPluginNotFound())
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.secret_meta_repo.get_metadata_for_secret.return_value = {
            'plugin_name': 'OldPlugin',
            'content_type': 'application/octet-stream',
        }
        secret_model = self._make_secret()

        self.assertRaises(
            crypto_base.CryptoPluginNotFound,
            resources.rewrap_secret,
            secret_model,
            self.project_model,
            self._make_secret_store(crypto_plugin='missing_crypto'))

        self.moc_plugin.store_secret.assert_not_called()

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_drops_none_metadata_and_defaults_content_type(
            self, mock_fullname, mock_get):
        """store_crypto returns None; k8s retrieve may omit content_type."""
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            None)
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {
            'secret_id': 'new-obj',
            'optional': None,
        }
        old_meta = {
            'plugin_name': 'K8sSecretStore',
            'namespace': 'barbican-secrets',
            'secret_name': 'barbican-secret-1',
        }
        new_meta = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'new-obj',
        }
        # payload check (no datums), already-on-target,
        # current_meta, then saved_meta
        self.secret_meta_repo.get_metadata_for_secret.side_effect = [
            old_meta, old_meta, old_meta, new_meta,
        ]
        secret_model = self._make_secret()

        resources.rewrap_secret(
            secret_model, self.project_model, self._make_secret_store())

        saved = self.secret_meta_repo.save.call_args[0][0]
        self.assertNotIn(None, saved.values())
        self.assertEqual('application/octet-stream', saved['content_type'])
        self.assertEqual('new-obj', saved['secret_id'])
        self.assertNotIn('optional', saved)
        self.secret_meta_repo.delete_for_secret.assert_called_once_with('sid')

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_kmip_style_metadata(self, mock_fullname, mock_get):
        """KMIP keeps the payload remotely; local DB has object metadata."""
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {
            'secret_id': 'kmip-new',
        }
        old_meta = {
            'plugin_name': 'KMIPSecretStore',
            'content_type': 'application/octet-stream',
            'secret_id': 'kmip-old',
        }
        new_meta = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'kmip-new',
        }
        # payload check (no datums), already-on-target,
        # current_meta, then saved_meta
        self.secret_meta_repo.get_metadata_for_secret.side_effect = [
            old_meta, old_meta, old_meta, new_meta,
        ]
        secret_model = self._make_secret()

        resources.rewrap_secret(
            secret_model, self.project_model,
            self._make_secret_store(store_plugin='kmip_plugin'))

        self.moc_plugin.store_secret.assert_called_once()
        self.moc_plugin.delete_secret.assert_called_once_with(old_meta)

    @mock.patch('barbican.plugin.resources._get_secret', autospec=True)
    @mock.patch('barbican.plugin.resources.utils.generate_fullname_for',
                autospec=True)
    def test_rewrap_secret_vault_style_metadata(self, mock_fullname, mock_get):
        """Vault/OpenBao keep the payload remotely like KMIP."""
        mock_fullname.return_value = 'NewPlugin'
        dto = secret_store.SecretDTO(
            secret_store.SecretType.OPAQUE,
            'c2VjcmV0',
            secret_store.KeySpec(),
            'application/octet-stream')
        mock_get.return_value = dto
        self.moc_plugin_manager.return_value.get_plugin_by_name.return_value \
            = self.moc_plugin
        self.moc_plugin.store_secret.return_value = {
            'secret_id': 'vault-new',
        }
        old_meta = {
            'plugin_name': 'VaultSecretStore',
            'content_type': 'application/octet-stream',
            'secret_id': 'vault-old',
        }
        new_meta = {
            'plugin_name': 'NewPlugin',
            'content_type': 'application/octet-stream',
            'secret_id': 'vault-new',
        }
        # payload check (no datums), already-on-target,
        # current_meta, then saved_meta
        self.secret_meta_repo.get_metadata_for_secret.side_effect = [
            old_meta, old_meta, old_meta, new_meta,
        ]
        secret_model = self._make_secret()

        resources.rewrap_secret(
            secret_model, self.project_model,
            self._make_secret_store(store_plugin='vault_plugin'))

        self.moc_plugin.store_secret.assert_called_once()
        self.moc_plugin.delete_secret.assert_called_once_with(old_meta)
