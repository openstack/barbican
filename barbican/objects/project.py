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
class Project(base.BarbicanObject, base.BarbicanPersistentObject,
              object_base.VersionedObjectDictCompat):

    fields = {
        'external_id': fields.StringField(nullable=True, default=None),
    }

    db_model = models.Project
    db_repo = repo.get_project_repository()

    @classmethod
    def find_by_external_project_id(cls, external_project_id,
                                    suppress_exception=False, session=None):
        project_db = cls.db_repo.find_by_external_project_id(
            external_project_id, suppress_exception, session)
        return cls()._from_db_object(project_db)
