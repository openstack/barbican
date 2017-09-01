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
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class ContainerSecret(base.BarbicanObject, base.BarbicanPersistentObject,
                      object_base.VersionedObjectDictCompat):
    fields = {
        'name': fields.StringField(nullable=True, default=None),
        'container_id': fields.StringField(),
        'secret_id': fields.StringField(),
    }

    db_model = models.ContainerSecret
    db_repo = repos.get_container_secret_repository()

    def create(self, session=None):
        change_fields = self._get_changed_persistent_fields()
        self._validate_fields(change_fields)
        db_entity = self._get_db_entity()
        db_entity.update(change_fields)
        db_entity = self.db_repo.create_from(db_entity, session=session)
        return self._from_db_object(db_entity)
