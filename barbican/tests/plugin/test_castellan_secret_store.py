# Copyright (c) 2018 Red Hat, Inc.
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

from castellan.common import exception
from castellan.common.objects import opaque_data

import barbican.plugin.castellan_secret_store as css
import barbican.plugin.interface.secret_store as ss
import barbican.plugin.vault_secret_store as vss
from barbican.tests import utils

key_ref1 = 'aff825be-6ede-4b1d-aeb0-aaec8e62aec6'
key_ref2 = '9c94c9c7-16ea-43e8-8ebe-0de282c0e6d5'

mock_key = b'\xae9Eso\xd4\x98\x04>\xc3\x05n\x0f\x03\x96\xa3' + \
           b'\xc3Z;\x9c\x11&oYY\x00\x13\xae\xf4>\x83\x82'


class WhenTestingVaultSecretStore(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingVaultSecretStore, self).setUp()
        self.key_manager_mock = mock.MagicMock(name="key manager mock")
        self.key_manager_mock.create_key_pair.return_value = (
            key_ref1, key_ref2
        )
        self.key_manager_mock.create_key.return_value = key_ref1
        self.key_manager_mock.store.return_value = key_ref1

        secret_object = opaque_data.OpaqueData(mock_key)
        self.key_manager_mock.get.return_value = secret_object

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.vault_plugin = mock.MagicMock(
            use_ssl=False,
            root_token_id='12345'
        )

        self.plugin = vss.VaultSecretStore(self.cfg_mock)
        self.plugin.key_manager = self.key_manager_mock
        self.plugin_name = "VaultSecretStore"

    def test_meta_dict(self):
        key_id = 'SOME_KEY_UUID'
        meta = self.plugin._meta_dict(key_id)
        self.assertNotIn(css.CastellanSecretStore.BIT_LENGTH, meta)
        self.assertNotIn(css.CastellanSecretStore.ALG, meta)
        self.assertEqual(key_id, meta[css.CastellanSecretStore.KEY_ID])

        meta = self.plugin._meta_dict(key_id, bit_length=128)
        self.assertEqual(128, meta[css.CastellanSecretStore.BIT_LENGTH])

        meta = self.plugin._meta_dict(key_id, algorithm='AES')
        self.assertEqual('AES', meta[css.CastellanSecretStore.ALG])

        self.assertEqual(1, meta[css.CastellanSecretStore.METADATA_VERSION])

    def test_generate_symmetric_key(self):
        key_spec = ss.KeySpec(ss.KeyAlgorithm.AES, 128)
        response = self.plugin.generate_symmetric_key(key_spec)

        self.plugin.key_manager.create_key.assert_called_once_with(
            mock.ANY,
            ss.KeyAlgorithm.AES,
            128
        )

        expected_response = {
            css.CastellanSecretStore.KEY_ID: key_ref1,
            css.CastellanSecretStore.METADATA_VERSION:
                css.CastellanSecretStore.CURRENT_VERSION}
        self.assertEqual(response, expected_response)

    def test_generate_symmetric_key_raises_exception(self):
        key_spec = ss.KeySpec(ss.KeyAlgorithm.AES, 128)
        self.plugin.key_manager.create_key.side_effect = exception.Forbidden()
        self.assertRaises(
            ss.SecretGeneralException,
            self.plugin.generate_symmetric_key,
            key_spec
        )

    def test_generate_asymmetric_key(self):
        key_spec = ss.KeySpec(ss.KeyAlgorithm.RSA, 2048)
        response = self.plugin.generate_asymmetric_key(key_spec)

        self.plugin.key_manager.create_key_pair.assert_called_once_with(
            mock.ANY,
            ss.KeyAlgorithm.RSA,
            2048)

        self.assertIsInstance(response, ss.AsymmetricKeyMetadataDTO)
        self.assertEqual(
            response.public_key_meta[css.CastellanSecretStore.KEY_ID],
            key_ref2
        )
        self.assertEqual(
            response.private_key_meta[css.CastellanSecretStore.KEY_ID],
            key_ref1
        )

    def test_generate_asymmetric_throws_exception(self):
        key_spec = ss.KeySpec(ss.KeyAlgorithm.RSA, 2048)
        self.plugin.key_manager.create_key_pair.side_effect = (
            exception.Forbidden()
        )
        self.assertRaises(
            ss.SecretGeneralException,
            self.plugin.generate_asymmetric_key,
            key_spec
        )

    def test_generate_asymmetric_throws_passphrase_exception(self):
        key_spec = ss.KeySpec(
            alg=ss.KeyAlgorithm.RSA,
            bit_length=2048,
            passphrase="some passphrase"
        )

        self.assertRaises(
            ss.GeneratePassphraseNotSupportedException,
            self.plugin.generate_asymmetric_key,
            key_spec
        )

    def test_store_secret(self):
        payload = b'encrypt me!!'
        key_spec = mock.MagicMock()
        content_type = mock.MagicMock()
        transport_key = None
        secret_dto = ss.SecretDTO(ss.SecretType.SYMMETRIC,
                                  base64.b64encode(payload),
                                  key_spec,
                                  content_type,
                                  transport_key)
        response = self.plugin.store_secret(secret_dto)

        data = opaque_data.OpaqueData(payload)
        self.plugin.key_manager.store.assert_called_once_with(
            mock.ANY,
            data
        )
        expected_response = self.plugin._meta_dict(key_ref1)
        self.assertEqual(response, expected_response)

    def test_store_secret_raises_exception(self):
        payload = b'encrypt me!!'
        key_spec = mock.MagicMock()
        content_type = mock.MagicMock()
        transport_key = None
        secret_dto = ss.SecretDTO(ss.SecretType.SYMMETRIC,
                                  base64.b64encode(payload),
                                  key_spec,
                                  content_type,
                                  transport_key)

        self.plugin.key_manager.store.side_effect = exception.Forbidden()
        self.assertRaises(
            ss.SecretGeneralException,
            self.plugin.store_secret,
            secret_dto
        )

    def test_get_secret(self):
        secret_metadata = self.plugin._meta_dict(key_ref1, 256, 'AES')

        response = self.plugin.get_secret(
            ss.SecretType.SYMMETRIC,
            secret_metadata
        )

        self.assertIsInstance(response, ss.SecretDTO)

        plaintext = base64.b64decode(response.secret)

        self.assertEqual(ss.SecretType.SYMMETRIC, response.type)
        self.assertEqual(mock_key, plaintext)
        self.plugin.key_manager.get.assert_called_once_with(
            mock.ANY,
            key_ref1
        )

    def test_get_secret_throws_exception(self):
        secret_metadata = self.plugin._meta_dict(key_ref1, 256, 'AES')
        self.plugin.key_manager.get.side_effect = exception.Forbidden()
        self.assertRaises(
            ss.SecretGeneralException,
            self.plugin.get_secret,
            ss.SecretType.SYMMETRIC,
            secret_metadata
        )

    def test_delete_secret(self):
        secret_metadata = {css.CastellanSecretStore.KEY_ID: key_ref1}
        self.plugin.delete_secret(secret_metadata)
        self.plugin.key_manager.delete.assert_called_once_with(
            mock.ANY,
            key_ref1
        )

    def test_delete_secret_throws_exception(self):
        secret_metadata = {css.CastellanSecretStore.KEY_ID: key_ref1}
        self.plugin.key_manager.delete.side_effect = exception.Forbidden()
        self.assertRaises(
            ss.SecretGeneralException,
            self.plugin.delete_secret,
            secret_metadata
        )

    def test_delete_secret_throws_key_error(self):
        secret_metadata = {css.CastellanSecretStore.KEY_ID: key_ref1}
        self.plugin.key_manager.delete.side_effect = KeyError()
        self.plugin.delete_secret(secret_metadata)
        self.plugin.key_manager.delete.assert_called_once_with(
            mock.ANY,
            key_ref1
        )

    def test_store_secret_supports(self):
        self.assertTrue(
            self.plugin.generate_supports(mock.ANY)
        )

    def test_generate_supports(self):
        self.assertTrue(
            self.plugin.generate_supports(mock.ANY)
        )

    def test_get_plugin_name(self):
        self.assertEqual(self.plugin_name, self.plugin.get_plugin_name())
