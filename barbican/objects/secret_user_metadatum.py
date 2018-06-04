#    Copyright 2018 Fujitsu.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_versionedobjects import base as object_base

from barbican.model import models
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class SecretUserMetadatum(base.BarbicanObject, base.BarbicanPersistentObject,
                          object_base.VersionedObjectDictCompat):

    fields = {
        'key': fields.StringField(),
        'value': fields.StringField(),
        'secret_id': fields.StringField(),
    }

    db_model = models.SecretStoreMetadatum
    db_repo = repo.get_secret_user_meta_repository()

    @classmethod
    def create_replace_user_metadata(cls, secret_id, metadata):
        cls.db_repo.create_replace_user_metadata(secret_id, metadata)

    @classmethod
    def get_metadata_for_secret(cls, secret_id):
        return cls.db_repo.get_metadata_for_secret(secret_id)

    @classmethod
    def create_replace_user_metadatum(cls, secret_id, key, value):
        cls.db_repo.create_replace_user_metadatum(secret_id, key, value)

    @classmethod
    def delete_metadatum(cls, secret_id, key):
        cls.db_repo.delete_metadatum(secret_id, key)
