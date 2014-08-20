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

from barbican.plugin.interface import secret_store
from barbican.plugin import store_crypto
import testtools


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
