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
import testtools

import barbican.model.repositories as repo
from barbican.plugin.interface import secret_store
from barbican.plugin import store_crypto
import mock


class WhenStoreCryptoAdapterPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenStoreCryptoAdapterPlugin, self).setUp()
        self.store_crypto = store_crypto.StoreCryptoAdapterPlugin()

    def tearDown(self):
        super(WhenStoreCryptoAdapterPlugin, self).tearDown()

    def test_generate_supports(self):
        """test generate_supports."""
        # key_spec should not be None
        self.assertFalse(self.store_crypto.generate_supports(None))
        self.key_spec = secret_store.KeySpec('AES', 64, 'CBC')
        self.assertEqual(secret_store.SecretType.SYMMETRIC,
                         self.store_crypto.generate_supports(self.key_spec))
        self.key_spec = secret_store.KeySpec('aes', 64, 'CBC')
        self.assertEqual(secret_store.SecretType.SYMMETRIC,
                         self.store_crypto.generate_supports(self.key_spec))


class WhenTestingStoreCrypto(testtools.TestCase):

    def setUp(self):
        super(WhenTestingStoreCrypto, self).setUp()
        self.store_crypto = store_crypto.StoreCryptoAdapterPlugin()

        self.content_type = 'application/octet-stream'
        self.tenant_model = mock.MagicMock()
        self.secret_dto = mock.MagicMock(cypher_text="asdasd")
        self.private_key_dto = mock.MagicMock(cypher_text="asdasd")
        self.public_key_dto = mock.MagicMock(cypher_text="asdasd")
        self.passphrase_dto = mock.MagicMock(cypher_text="asdasd")

        tenant_repo = mock.MagicMock()
        secret_repo = mock.MagicMock()
        secret_repo.create_from.return_value = None
        container_repo = mock.MagicMock()
        container_repo.create_from.return_value = None
        container_secret_repo = mock.MagicMock()
        container_secret_repo.create_from.return_value = None
        tenant_secret_repo = mock.MagicMock()
        tenant_secret_repo.create_from.return_value = None
        secret_meta_repo = mock.MagicMock()
        secret_meta_repo.create_from.return_value = None
        kek_repo = mock.MagicMock()
        kek_repo.create_from.return_value = None
        datum_repo = mock.MagicMock()
        datum_repo.create_from.return_value = None

        self.repos = repo.Repositories(container_repo=container_repo,
                                       container_secret_repo=
                                       container_secret_repo,
                                       tenant_repo=tenant_repo,
                                       secret_repo=secret_repo,
                                       tenant_secret_repo=tenant_secret_repo,
                                       secret_meta_repo=secret_meta_repo,
                                       kek_repo=kek_repo,
                                       datum_repo=datum_repo)

        self.context = secret_store.\
            SecretStoreContext(content_type=self.content_type,
                               secret_model=mock.MagicMock(),
                               private_secret_model=mock.MagicMock(),
                               public_secret_model=mock.MagicMock(),
                               passphrase_secret_model=mock.MagicMock(),
                               tenant_model=mock.MagicMock(),
                               repos=self.repos)

        self.generating_plugin = mock.MagicMock()
        self._config_crypto_plugin(self.generating_plugin)

    def tearDown(self):
        super(WhenTestingStoreCrypto, self).tearDown()

    def _config_crypto_plugin(self, plugin):
        """Mock the crypto plugin."""

        gen_plugin_config = {
            'get_plugin_store_generate.return_value':
            plugin
        }
        self.gen_plugin_patcher = mock.patch(
            'barbican.plugin.crypto.manager'
            '.PLUGIN_MANAGER',
            **gen_plugin_config
        )
        self.gen_plugin_patcher.start()

    def test_store_secret(self):
        """test store_secret."""
        self.encrypting_plugin = mock.MagicMock()
        self.encrypting_plugin.encrypt.return_value = self.secret_dto
        self._config_crypto_plugin(self.encrypting_plugin)

        response_dic = \
            self.store_crypto.\
            store_secret(self.secret_dto,
                         self.context)

        self.assertEqual(None, response_dic)
        self.assertEqual(self.encrypting_plugin.encrypt.
                         call_count, 1)
        self.assertEqual(self.repos.datum_repo.create_from.
                         call_count, 1)

    def test_generate_symmetric_key(self):
        """test symmetric secret generation."""
        self.spec = secret_store.KeySpec('AES', 64, 'CBC')

        self.generating_plugin.generate_symmetric.\
            return_value = (self.secret_dto)

        response_dic = \
            self.store_crypto.\
            generate_symmetric_key(self.spec,
                                   self.context)

        self.assertEqual(None, response_dic)
        self.assertEqual(self.generating_plugin.generate_symmetric.
                         call_count, 1)
        self.assertEqual(self.repos.datum_repo.create_from.
                         call_count, 1)

    def test_generate_asymmetric_key_with_passphrase(self):
        """test asymmetric secret generation with passphrase."""
        self.spec = secret_store.KeySpec('RSA', 1024, passphrase='changeit')
        self.generating_plugin.generate_asymmetric.\
            return_value = (self.private_key_dto,
                            self.public_key_dto,
                            self.passphrase_dto)

        response_dto = \
            self.store_crypto.\
            generate_asymmetric_key(self.spec,
                                    self.context)

        self.assertEqual(None, response_dto.private_key_meta)
        self.assertEqual(None, response_dto.public_key_meta)
        self.assertEqual(None, response_dto.passphrase_meta)
        self.assertEqual(self.generating_plugin.generate_asymmetric.
                         call_count, 1)
        self.assertEqual(self.repos.datum_repo.create_from.
                         call_count, 3)

    def test_generate_asymmetric_key_without_passphrase(self):
        """test asymmetric secret generation without passphrase."""
        self.spec = secret_store.KeySpec('RSA', 1024)
        self.generating_plugin.\
            generate_asymmetric.return_value = (self.private_key_dto,
                                                self.public_key_dto,
                                                None)
        response_dto = \
            self.store_crypto.\
            generate_asymmetric_key(self.spec,
                                    self.context)

        self.assertEqual(None, response_dto.private_key_meta)
        self.assertEqual(None, response_dto.public_key_meta)
        self.assertEqual(None, response_dto.passphrase_meta)
        self.assertEqual(self.generating_plugin.generate_asymmetric.
                         call_count, 1)
        self.assertEqual(self.repos.datum_repo.create_from.
                         call_count, 2)
