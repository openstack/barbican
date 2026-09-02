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

from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingSecretStoreMetadatumRepository(
        database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingSecretStoreMetadatumRepository, self).setUp()
        self.repo = repositories.get_secret_meta_repository()

    def _create_secret(self):
        session = self.repo.get_session()
        project = models.Project()
        project.external_id = "keystone_project_id"
        project.save(session=session)

        secret = models.Secret()
        secret.project_id = project.id
        secret_repo = repositories.get_secret_repository()
        secret = secret_repo.create_from(secret, session=session)
        secret.save(session=session)
        session.commit()
        return secret

    def test_save_skips_none_values(self):
        """None values must not create SecretStoreMetadatum rows.

        SecretStoreMetadatum.value is non-nullable and the model
        constructor rejects None. Callers may still pass optional plugin
        fields as
        None in the metadata dict; skip those keys instead of raising.
        """
        secret = self._create_secret()
        self.repo.save(
            {
                'plugin_name': 'store_crypto',
                'optional_field': None,
                'content_type': 'application/octet-stream',
            },
            secret)

        metadata = self.repo.get_metadata_for_secret(secret.id)
        self.assertEqual(
            {
                'plugin_name': 'store_crypto',
                'content_type': 'application/octet-stream',
            },
            metadata)
        self.assertNotIn('optional_field', metadata)
