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
class ProjectQuotas(base.BarbicanObject, base.BarbicanPersistentObject,
                    object_base.VersionedObjectDictCompat):
    fields = {
        'project_id': fields.StringField(nullable=True),
        'secrets': fields.IntegerField(nullable=True, default=None),
        'containers': fields.IntegerField(nullable=True, default=None),
        'consumers': fields.IntegerField(nullable=True, default=None),
        'orders': fields.IntegerField(nullable=True, default=None),
        'cas': fields.IntegerField(nullable=True, default=None),
        'project': fields.ObjectField('Project', nullable=True, default=None),
    }

    db_model = models.ProjectQuotas
    db_repo = repos.get_project_quotas_repository()
    synthetic_fields = ['project']

    def _validate_fields(self, change_fields):
        msg = u._("Must supply non-None {0} argument for ProjectQuotas entry.")

        if not change_fields.get('project_id'):
            raise exception.MissingArgumentError(msg.format("project_id"))

    def _get_db_entity(self, parsed_project_quotas=None):
        return self.db_model(parsed_project_quotas=parsed_project_quotas,
                             check_exc=False)

    def create(self, session=None, parsed_project_quotas=None):
        change_fields = self._get_changed_persistent_fields()
        self._validate_fields(change_fields)
        db_entity = self._get_db_entity(
            parsed_project_quotas=parsed_project_quotas)
        db_entity.update(change_fields)
        db_entity = self.db_repo.create_from(db_entity, session=session)
        self._from_db_object(db_entity)

    @classmethod
    def get_by_create_date(cls, offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        entities_db, offset, limit, total = \
            cls.db_repo.get_by_create_date(offset_arg, limit_arg,
                                           suppress_exception, session)
        entities = [cls()._from_db_object(entity_db)
                    for entity_db in entities_db]
        return entities, offset, limit, total

    @classmethod
    def create_or_update_by_project_id(cls, project_id,
                                       parsed_project_quotas,
                                       session=None):
        cls.db_repo.create_or_update_by_project_id(project_id,
                                                   parsed_project_quotas,
                                                   session)

    @classmethod
    def get_by_external_project_id(cls, external_project_id,
                                   suppress_exception=False, session=None):
        entity_db = cls.db_repo. \
            get_by_external_project_id(external_project_id,
                                       suppress_exception, session)
        return cls()._from_db_object(entity_db)

    @classmethod
    def delete_by_external_project_id(cls, external_project_id,
                                      suppress_exception=False, session=None):
        cls.db_repo.delete_by_external_project_id(external_project_id,
                                                  suppress_exception,
                                                  session)
