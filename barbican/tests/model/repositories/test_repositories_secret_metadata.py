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
from barbican.tests import utils


@utils.parameterized_test_case
class WhenTestingSecretMetadataRepository(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingSecretMetadataRepository, self).setUp()
        self.repo = repositories.SecretUserMetadatumRepo()

        self.test_metadata = {
            "dog": "poodle",
            "cat": "siamese"
        }

    def _create_base_secret(self, project_id=None):
        # Setup the secret and needed base relationship
        secret_repo = repositories.get_secret_repository()
        session = secret_repo.get_session()

        if project_id is None:  # don't re-create project if it created earlier
            project = models.Project()
            project.external_id = "keystone_project_id"
            project.save(session=session)
            project_id = project.id

        secret_model = models.Secret()
        secret_model.project_id = project_id
        secret = secret_repo.create_from(secret_model, session=session)

        secret.save(session=session)
        session.commit()
        return secret

    def test_create_and_get_metadata_for_secret(self):
        secret = self._create_base_secret()

        self.repo.create_replace_user_metadata(secret.id,
                                               self.test_metadata)
        metadata = self.repo.get_metadata_for_secret(secret.id)
        self.assertEqual(self.test_metadata, metadata)

    def test_get_metadata_invalid_secret(self):
        metadata = self.repo.get_metadata_for_secret("invalid_id")
        self.assertEqual({}, metadata)

    def test_create_user_metadatum(self):
        secret = self._create_base_secret()

        self.repo.create_replace_user_metadata(secret.id,
                                               self.test_metadata)

        # adds a new key
        self.repo.create_replace_user_metadatum(secret.id,
                                                'lizard',
                                                'green anole')

        self.test_metadata['lizard'] = 'green anole'
        metadata = self.repo.get_metadata_for_secret(secret.id)

        self.assertEqual(self.test_metadata, metadata)

    def test_replace_user_metadatum(self):
        secret = self._create_base_secret()

        self.repo.create_replace_user_metadata(secret.id,
                                               self.test_metadata)

        # updates existing key
        self.repo.create_replace_user_metadatum(secret.id,
                                                'dog',
                                                'rat terrier')

        self.test_metadata['dog'] = 'rat terrier'
        metadata = self.repo.get_metadata_for_secret(secret.id)

        self.assertEqual(self.test_metadata, metadata)

    def test_delete_user_metadatum(self):
        secret = self._create_base_secret()

        self.repo.create_replace_user_metadata(secret.id,
                                               self.test_metadata)

        # deletes existing key
        self.repo.delete_metadatum(secret.id,
                                   'cat')

        del self.test_metadata['cat']
        metadata = self.repo.get_metadata_for_secret(secret.id)

        self.assertEqual(self.test_metadata, metadata)

    def test_delete_secret_deletes_secret_metadata(self):
        secret = self._create_base_secret()

        self.repo.create_replace_user_metadata(secret.id,
                                               self.test_metadata)

        metadata = self.repo.get_metadata_for_secret(secret.id)
        self.assertEqual(self.test_metadata, metadata)

        # deletes existing secret
        secret.delete()

        metadata = self.repo.get_metadata_for_secret(secret.id)
        self.assertEqual({}, metadata)
