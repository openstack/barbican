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
class SecretACLUser(base.BarbicanObject, base.BarbicanPersistentObject,
                    object_base.VersionedObjectDictCompat):

    fields = {
        'acl_id': fields.StringField(),
        'user_id': fields.StringField(),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.SecretACLUser
    db_repo = repos.get_secret_acl_user_repository()

    def _validate_fields(self, change_fields):
        if change_fields.get('user_id') is None:
            msg = u._(
                "Must supply non-None {0} argument for SecretACLUser entry.")
            raise exception.MissingArgumentError(msg.format("user_id"))

    def delete(self, session):
        entity_id = self.id
        self.db_repo.delete_entity_by_id(
            entity_id=entity_id, external_project_id=None, session=session)
