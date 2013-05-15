# Copyright (c) 2013 Rackspace, Inc.
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

from barbican.crypto.plugin import CryptoPluginBase
from barbican.model.models import EncryptedDatum
from barbican.openstack.common import jsonutils as json


class TestCryptoPlugin(CryptoPluginBase):
    """Crypto plugin implementation for testing the plugin manager."""

    def encrypt(self, unencrypted, secret, tenant):
        datum = EncryptedDatum(secret)
        datum.cypher_text = 'cypher_text'
        datum.mime_type = 'text/plain'
        datum.kek_metadata = json.dumps({'plugin': 'TestCryptoPlugin'})
        return datum

    def decrypt(self, secret_type, secret, tenant):
        encrypted_datum = secret.encrypted_data
        return 'plain-data'

    def create(self, secret_type):
        return "insecure_key"

    def supports(self, secret_type):
        return secret_type == 'text/plain'
