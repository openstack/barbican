# Copyright 2025 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cryptography import fernet

from barbican.cmd import kek_rewrap
from barbican.common import utils
from barbican.plugin.crypto import simple_crypto


CONF = simple_crypto.CONF


class SimpleCryptoKEKRewrap(kek_rewrap.BaseKEKRewrap):

    def __init__(self, conf):
        super().__init__(conf)

        self.crypto_plugin = simple_crypto.SimpleCryptoPlugin(conf)
        self.plugin_name = utils.generate_fullname_for(self.crypto_plugin)
        self.master_keys = conf.simple_crypto_plugin.kek

    def rewrap_kek(self, project, kek):
        with self.db_session.begin():
            encrypted_pkek = kek.plugin_meta

            if self.dry_run:
                print("Would have rotated PKEK {}".format(kek.kek_label))
                return

            encryptor = fernet.MultiFernet(
                [fernet.Fernet(mkek) for mkek in self.master_keys]
            )
            rotated_pkek = encryptor.rotate(encrypted_pkek)
            kek.plugin_meta = rotated_pkek
