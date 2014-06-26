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

import mock
import os
import tempfile
import testtools

try:
    import barbican.plugin.dogtag as dogtag_import
    import barbican.plugin.interface.secret_store as sstore
    imports_ok = True
except ImportError:
    # dogtag imports probably not available
    imports_ok = False


class WhenTestingDogtagPlugin(testtools.TestCase):

    def setUp(self):
        super(WhenTestingDogtagPlugin, self).setUp()
        if not imports_ok:
            return

        self.keyclient_mock = mock.MagicMock(name="KeyClient mock")
        self.patcher = mock.patch('pki.cryptoutil.NSSCryptoUtil')
        self.patcher.start()

        # create nss db for test only
        self.nss_dir = tempfile.mkdtemp()

        self.cfg_mock = mock.MagicMock(name='config mock')
        self.cfg_mock.dogtag_plugin = mock.MagicMock(
            nss_db_path=self.nss_dir)
        self.plugin = dogtag_import.DogtagPlugin(self.cfg_mock)
        self.plugin.keyclient = self.keyclient_mock

    def tearDown(self):
        super(WhenTestingDogtagPlugin, self).tearDown()
        if not imports_ok:
            return
        self.patcher.stop()
        os.rmdir(self.nss_dir)

    def test_generate(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 128)
        self.plugin.generate_symmetric_key(key_spec)

        self.keyclient_mock.generate_symmetric_key.assert_called_once_with(
            mock.ANY,
            sstore.KeyAlgorithm.AES.upper(),
            128,
            mock.ANY)

    def test_generate_non_supported_algorithm(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.EC, 192)
        self.assertRaises(
            dogtag_import.DogtagPluginAlgorithmException,
            self.plugin.generate_symmetric_key,
            key_spec
        )

    def test_raises_error_with_no_pem_path(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(pem_path=None)
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagPlugin,
            m,
        )

    def test_raises_error_with_no_pem_password(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(pem_password=None)
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagPlugin,
            m,
        )

    def test_raises_error_with_no_nss_password(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        m = mock.MagicMock()
        m.dogtag_plugin = mock.MagicMock(nss_password=None)
        self.assertRaises(
            ValueError,
            dogtag_import.DogtagPlugin,
            m,
        )

    def test_store_secret(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        payload = 'encrypt me!!'
        secret_dto = sstore.SecretDTO(sstore.SecretType.SYMMETRIC,
                                      sstore.KeyFormat.RAW,
                                      payload,
                                      mock.MagicMock())
        self.plugin.store_secret(secret_dto)
        self.keyclient_mock.archive_key.assert_called_once_with(
            mock.ANY,
            "passPhrase",
            payload,
            key_algorithm=None,
            key_size=None)

    def test_get_secret(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        secret_metadata = {
            dogtag_import.DogtagPlugin.SECRET_FORMAT: sstore.KeyFormat.RAW,
            dogtag_import.DogtagPlugin.SECRET_TYPE:
            sstore.SecretType.SYMMETRIC,
            dogtag_import.DogtagPlugin.SECRET_KEYSPEC: mock.MagicMock(),
            dogtag_import.DogtagPlugin.KEY_ID: 'key1'
        }
        self.plugin.get_secret(secret_metadata)

        self.keyclient_mock.retrieve_key.assert_called_once_with('key1')

    def test_supports_symmetric_aes_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.AES, 256)
        self.assertTrue(
            self.plugin.generate_supports(key_spec)
        )

    def test_supports_asymmetric_ec_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.EC, 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )

    def test_supports_symmetric_dh_key_generation(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec(sstore.KeyAlgorithm.DIFFIE_HELLMAN, 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )

    def test_does_not_support_unknown_type(self):
        if not imports_ok:
            self.skipTest("Dogtag imports not available")
        key_spec = sstore.KeySpec("SOMETHING_RANDOM", 156)
        self.assertFalse(
            self.plugin.generate_supports(key_spec)
        )
