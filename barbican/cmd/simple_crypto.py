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
import base64

from cryptography import fernet

from barbican.cmd import kek_rewrap
from barbican.common import resources
from barbican.common import utils
from barbican.model import repositories
from barbican.plugin.crypto import base
from barbican.plugin.crypto import simple_crypto
from barbican.plugin import store_crypto


CONF = simple_crypto.CONF


class SimpleCryptoCmd:

    def __init__(self, conf):
        self.crypto_plugin = simple_crypto.SimpleCryptoPlugin(conf)
        self.crypto_plugin_name = utils.generate_fullname_for(
            self.crypto_plugin
        )
        repositories.setup_database_engine_and_factory()
        self.kek_repo = repositories.get_kek_datum_repository()

    def new_pkek(self, external_id):
        """Creates a new Project-specific KEK

        :param str external_id:  Project ID as defined by the external identity
            system.  e.g. Keystone Project ID.
        """
        print(f"Generating new pKEK for {external_id}")
        project = resources.get_or_create_project(external_id)
        _ = self.kek_repo.create_kek_datum(project, self.crypto_plugin_name)
        repositories.commit()

    def rewrap_secrets(self, external_id):
        project = resources.get_or_create_project(external_id)
        active_kek, active_kek_dto = store_crypto._find_or_create_kek_objects(
            self.crypto_plugin, project
        )
        print(f"Rewrapping Secrets for Project {external_id} using "
              f"{active_kek.id}")
        for secret in project.secrets:
            if secret.deleted:
                continue
            print(f"Rewrapping Secret {secret.id}")
            encrypted_datum = secret.encrypted_data[0]
            response = self.crypto_plugin.rewrap(
                base.DecryptDTO(base64.b64decode(encrypted_datum.cypher_text)),
                base.KEKMetaDTO(encrypted_datum.kek_meta_project),
                encrypted_datum.kek_meta_extended,
                active_kek_dto,
                # NOTE(dmendiza):
                # barbican.plugin.crypto.base.CryptoPluginBase methods
                # take a project_id but it is unclear if this should be
                # project.id or project.external_id.  In any case,
                # siple_crypto does not seem to use it for anything.
                project.id)
            encrypted_datum.cypher_text = base64.b64encode(
                response.cypher_text)
            encrypted_datum.kek_meta_project = active_kek
            encrypted_datum.save()
        repositories.commit()


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
