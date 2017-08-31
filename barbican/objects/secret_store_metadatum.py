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
from oslo_utils import timeutils
from oslo_versionedobjects import base as object_base

from barbican.common import exception
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class SecretStoreMetadatum(base.BarbicanObject, base.BarbicanPersistentObject,
                           object_base.VersionedObjectDictCompat):
    fields = {
        'key': fields.StringField(),
        'value': fields.StringField(),
        'secret_id': fields.StringField()
    }

    db_model = models.SecretStoreMetadatum
    db_repo = repo.get_secret_meta_repository()

    def _validate_fields(self, change_fields):

        msg = u._("Must supply non-None {0} argument "
                  "for SecretStoreMetadatum entry.")

        if change_fields.get('key') is None:
            raise exception.MissingArgumentError(msg.format('key'))
        if change_fields.get('value') is None:
            raise exception.MissingArgumentError(msg.format('value'))

    @classmethod
    def save(cls, metadata, secret_obj):
        """Saves the specified metadata for the secret."""
        now = timeutils.utcnow()
        for k, v in metadata.items():
            meta_obj = cls(key=k, value=v)
            meta_obj.updated_at = now
            meta_obj.secret_id = secret_obj.id
            meta_obj.create()

    @classmethod
    def get_metadata_for_secret(cls, secret_id):
        return cls.db_repo.get_metadata_for_secret(secret_id)
