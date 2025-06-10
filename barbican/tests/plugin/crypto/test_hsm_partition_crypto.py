# Copyright (c) 2025 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from oslo_config import cfg
from barbican.common import config, exception
from barbican.model.models import ProjectHSMPartition, HSMPartitionConfig, KEKDatum
from barbican.plugin.crypto import hsm_partition_crypto
from barbican.plugin.crypto.base import ResponseDTO, KEKMetaDTO
from barbican.plugin.crypto import p11_crypto
from barbican.tests import utils


class WhenTestingHSMPartitionCryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingHSMPartitionCryptoPlugin, self).setUp()

        self.conf = config.new_config()
        self.conf.register_group(hsm_partition_crypto.hsm_partition_crypto_plugin_group)
        self.conf.register_opts(hsm_partition_crypto.hsm_partition_crypto_plugin_opts,
                                group=hsm_partition_crypto.hsm_partition_crypto_plugin_group)

        self.pkcs11 = mock.Mock()
        self.plugin_name = 'TestHSMPartitionCryptoPlugin'
        self.project_id = 'test_project_id'
        self.partition_id = 'test_partition_id'
        self.slot_id = '100'
        self.token_label = 'test_token_label'
        self.library_path = 'test_library_path'
        self.login = 'test_password'
        self.cypher_text = b'cypher_text'
        self.kek_meta_extended = ('{"iv":"AAAA",'
                                  '"mechanism":"CKM_AES_CBC",'
                                  '"key_wrap_mechanism":"CKM_AES_CBC_PAD"}')

        self.conf.hsm_partition_crypto_plugin.plugin_name = self.plugin_name
        self.conf.hsm_partition_crypto_plugin.default_partition_id = self.partition_id

    def test_init_with_global_conf(self):
        store_plugin_name = 'default'
        section_name = 'hsm_partition_crypto_plugin'

        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin()

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_init_with_given_conf(self):
        store_plugin_name = 'given_test_store_plugin'
        section_name = f'hsm_partition_crypto_plugin:{store_plugin_name}'

        plugin_group = cfg.OptGroup(name=section_name)
        self.conf.register_group(plugin_group)
        self.conf.register_opts(hsm_partition_crypto.hsm_partition_crypto_plugin_opts, group=plugin_group)

        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name
        )

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_init_with_dynamic_conf(self):
        store_plugin_name = 'dynamic_test_store_plugin'
        section_name = f'hsm_partition_crypto_plugin:{store_plugin_name}'

        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name
        )

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_get_partition_for_project_raises_error_without_project_id(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin()

        self.assertRaises(ValueError, plugin._get_partition_for_project, None)

    def test_get_partition_for_project_specific_mapping(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)

        plugin.project_hsm_repo = mock.MagicMock()
        plugin.project_hsm_repo.get_by_project_id.return_value = ProjectHSMPartition(
            project_id=self.project_id,
            partition_id=self.partition_id,
        )
        plugin.hsm_partition_repo = mock.MagicMock()
        plugin.hsm_partition_repo.get_by_id.return_value = HSMPartitionConfig(
            project_id=self.project_id,
            slot_id=self.slot_id,
            token_label=self.token_label,
        )

        partition = plugin._get_partition_for_project(self.project_id)

        self.assertEqual(self.project_id, partition.project_id)
        self.assertEqual(self.slot_id, partition.slot_id)
        self.assertEqual(self.token_label, partition.token_label)

    def test_get_partition_for_default_mapping(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)

        plugin.project_hsm_repo = mock.MagicMock()
        plugin.project_hsm_repo.get_by_project_id.side_effect = Exception('Mapping not found')
        plugin.hsm_partition_repo = mock.MagicMock()
        plugin.hsm_partition_repo.get_by_id.return_value = HSMPartitionConfig(
            project_id=self.project_id,
            slot_id=self.slot_id,
            token_label=self.token_label,
        )

        partition = plugin._get_partition_for_project(self.project_id)

        self.assertEqual(self.project_id, partition.project_id)
        self.assertEqual(self.slot_id, partition.slot_id)
        self.assertEqual(self.token_label, partition.token_label)

    def test_get_partition_raises_error_for_no_mapping(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)

        plugin.project_hsm_repo = mock.MagicMock()
        plugin.project_hsm_repo.get_by_project_id.side_effect = Exception('Mapping not found')
        plugin.hsm_partition_repo = mock.MagicMock()
        plugin.hsm_partition_repo.get_by_id.side_effect = exception.NotFound('Partition not found')

        self.assertRaises(ValueError, plugin._get_partition_for_project, self.project_id)

    def test_configure_pkcs11_is_already_configured(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)
        plugin.current_project_id = self.project_id
        plugin.pkcs11 = mock.MagicMock()
        plugin._get_partition_for_project = mock.MagicMock()

        plugin._configure_pkcs11(self.project_id)

        self.assertEqual(0, plugin._get_partition_for_project.call_count)

    def test_configure_pkcs11_raises_error_for_no_partition_mapping(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)
        plugin._get_partition_for_project = mock.MagicMock()
        plugin._get_partition_for_project.return_value = None

        self.assertRaises(ValueError, plugin._configure_pkcs11, self.project_id)

    def test_configure_pkcs11(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(conf=self.conf)
        plugin._get_partition_for_project = mock.MagicMock()
        plugin._get_partition_for_project.return_value = HSMPartitionConfig(
            project_id=self.project_id,
            slot_id=self.slot_id,
            token_label=self.token_label,
            credentials={'library_path': self.library_path, 'password': self.login},

        )
        plugin._create_pkcs11 = mock.MagicMock()
        plugin._create_pkcs11.return_value = self.pkcs11

        plugin._configure_pkcs11(self.project_id)

        self.assertEqual(self.library_path, plugin.library_path)
        self.assertEqual(self.login, plugin.login)
        self.assertEqual(int(self.slot_id), plugin.slot_id)
        self.assertEqual([self.token_label], plugin.token_labels)
        self.assertEqual(1, plugin._create_pkcs11.call_count)

    def test_get_plugin_name_for_default_store_plugin_name(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(
            conf=self.conf
        )

        self.assertEqual(self.plugin_name, plugin.get_plugin_name())

    def test_get_plugin_name_for_given_store_plugin_name(self):
        store_plugin_name = 'test_store_plugin'
        plugin_group_name = f'hsm_partition_crypto_plugin:{store_plugin_name}'

        plugin_group = cfg.OptGroup(name=plugin_group_name)
        self.conf.register_group(plugin_group)
        self.conf.register_opts(hsm_partition_crypto.hsm_partition_crypto_plugin_opts, group=plugin_group)

        self.conf[plugin_group_name].plugin_name = self.plugin_name

        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name
        )

        self.assertEqual(self.plugin_name, plugin.get_plugin_name())

    def test_encrypt(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(p11_crypto.P11CryptoPlugin, 'encrypt') as mock_encrypt:
            mock_encrypt.return_value = ResponseDTO(
                cypher_text=self.cypher_text,
                kek_meta_extended=self.kek_meta_extended,
            )

            response_dto = plugin.encrypt(
                encrypt_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_encrypt.call_count)
        self.assertEqual(self.cypher_text, response_dto.cypher_text)
        self.assertEqual(self.kek_meta_extended, response_dto.kek_meta_extended)

    def test_decrypt(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(p11_crypto.P11CryptoPlugin, 'decrypt') as mock_decrypt:
            mock_decrypt.return_value = b'0'

            pt = plugin.decrypt(
                decrypt_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                kek_meta_extended=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_decrypt.call_count)
        self.assertEqual(b'0', pt)

    def test_generate_symmetric(self):
        plugin = hsm_partition_crypto.HSMPartitionCryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(p11_crypto.P11CryptoPlugin, 'generate_symmetric') as mock_generate_symmetric:
            mock_generate_symmetric.return_value = ResponseDTO(
                cypher_text=self.cypher_text,
                kek_meta_extended=self.kek_meta_extended,
            )

            response_dto = plugin.generate_symmetric(
                generate_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_generate_symmetric.call_count)
        self.assertEqual(self.cypher_text, response_dto.cypher_text)
        self.assertEqual(self.kek_meta_extended, response_dto.kek_meta_extended)
