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

from barbican.common import exception
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class SecretStores(base.BarbicanObject, base.BarbicanPersistentObject,
                   object_base.VersionedObjectDictCompat):
    fields = {
        'store_plugin': fields.StringField(),
        'crypto_plugin': fields.StringField(nullable=True),
        'global_default': fields.BooleanField(default=False),
        'name': fields.StringField(),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.SecretStores
    db_repo = repos.get_secret_stores_repository()

    def _validate_fields(self, change_fields):
        msg = u._("Must supply non-Blank {0} argument for SecretStores entry.")

        if not change_fields.get('name'):
            raise exception.MissingArgumentError(msg.format("name"))
        if not change_fields.get('store_plugin'):
            raise exception.MissingArgumentError(msg.format("store_plugin"))

    @classmethod
    def get_all(cls, session=None):
        secret_stores_db = cls.db_repo.get_all(session)
        secret_stores_obj = [cls()._from_db_object(secret_store_db) for
                             secret_store_db in secret_stores_db]
        return secret_stores_obj
