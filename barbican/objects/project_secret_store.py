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
class ProjectSecretStore(base.BarbicanObject, base.BarbicanPersistentObject,
                         object_base.VersionedObjectDictCompat):
    fields = {
        'secret_store_id': fields.StringField(nullable=True, default=None),
        'project_id': fields.StringField(nullable=True, default=None),
        'secret_store': fields.ObjectField('SecretStores',
                                           nullable=True, default=None),
        'project': fields.ObjectField('Project', nullable=True, default=None),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.ProjectSecretStore
    db_repo = repos.get_project_secret_store_repository()
    synthetic_fields = ['secret_store', 'project']

    def _validate_fields(self, change_fields):

        msg = u._("Must supply non-None {0} argument for ProjectSecretStore "
                  " entry.")

        if not change_fields.get('project_id'):
            raise exception.MissingArgumentError(msg.format("project_id"))
        if not change_fields.get('secret_store_id'):
            raise exception.MissingArgumentError(msg.format("secret_store_id"))

    @classmethod
    def get_secret_store_for_project(cls, project_id, external_project_id,
                                     suppress_exception=False, session=None):
        pss_db = cls.db_repo.get_secret_store_for_project(
            project_id,
            external_project_id,
            suppress_exception,
            session)
        return cls()._from_db_object(pss_db)

    @classmethod
    def create_or_update_for_project(cls, project_id, secret_store_id,
                                     session=None):
        pss_db = cls.db_repo.create_or_update_for_project(project_id,
                                                          secret_store_id,
                                                          session)

        return cls()._from_db_object(pss_db)

    @classmethod
    def get_count_by_secret_store(cls, secret_store_id, session=None):
        number_pss = cls.db_repo.get_count_by_secret_store(secret_store_id,
                                                           session)
        return number_pss
