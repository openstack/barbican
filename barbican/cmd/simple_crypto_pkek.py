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
from barbican.common import resources
from barbican.common import utils
from barbican.model import repositories
from barbican.plugin.crypto import simple_crypto


CONF = simple_crypto.CONF


class SimpleCryptoPKEK:

    def __init__(self, conf):
        self.crypto_plugin = simple_crypto.SimpleCryptoPlugin(conf)
        self.crypto_plugin_name = utils.generate_fullname_for(
            self.crypto_plugin
        )
        repositories.setup_database_engine_and_factory()

    def new_pkek(self, external_id):
        """Creates a new Project-specific KEK

        :param str external_id:  Project ID as defined by the external identity
            system.  e.g. Keystone Project ID.
        """
        print(f"Generating new pKEK for {external_id}")
        project = resources.get_or_create_project(external_id)
        kek_repo = repositories.get_kek_datum_repository()
        _ = kek_repo.create_kek_datum(project, self.crypto_plugin_name)
        repositories.commit()
