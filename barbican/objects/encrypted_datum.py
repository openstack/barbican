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
class EncryptedDatum(base.BarbicanObject, base.BarbicanPersistentObject,
                     object_base.VersionedObjectDictCompat):

    fields = {
        'content_type': fields.StringField(nullable=True, default=None),
        'secret_id': fields.StringField(),
        'kek_id': fields.StringField(),
        'cypher_text': fields.StringField(nullable=True, default=None),
        'kek_meta_extended': fields.StringField(nullable=True, default=None),
        'kek_meta_project': fields.ObjectField('KEKDatum',
                                               nullable=True, default=None),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.EncryptedDatum
    db_repo = repo.get_encrypted_datum_repository()
    synthetic_fields = ['kek_meta_project']
