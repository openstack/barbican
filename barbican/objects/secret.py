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

from barbican.common import utils
from barbican.model import models
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class Secret(base.BarbicanObject, base.BarbicanPersistentObject,
             object_base.VersionedObjectDictCompat):
    """This class represents Secret object"""

    fields = {
        'name': fields.StringField(nullable=True),
        'secret_type': fields.StringField(nullable=True,
                                          default=utils.SECRET_TYPE_OPAQUE),
        'expiration': fields.DateTimeField(nullable=True, default=None),
        'algorithm': fields.StringField(nullable=True, default=None),
        'bit_length': fields.IntegerField(nullable=True, default=None),
        'mode': fields.StringField(nullable=True, default=None),
        'creator_id': fields.StringField(nullable=True, default=None),
        'project_id': fields.StringField(nullable=True, default=None),
        'encrypted_data': fields.ListOfObjectsField('EncryptedDatum',
                                                    default=list(),
                                                    nullable=True),
        'secret_acls': fields.ListOfObjectsField('SecretACL',
                                                 default=list(),
                                                 nullable=True),
        'secret_store_metadata':
            fields.DictOfObjectsField('SecretStoreMetadatum', default=dict(),
                                      nullable=True),
        'secret_user_metadata': fields.DictOfObjectsField(
            'SecretUserMetadatum',
            default=dict(),
            nullable=True),
        'consumers': fields.ListOfObjectsField('SecretConsumerMetadatum',
                                               default=list(),
                                               nullable=True),

        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.Secret
    db_repo = repo.get_secret_repository()
    synthetic_fields = ['encrypted_data', 'secret_acls',
                        'secret_store_metadata', 'secret_user_metadata',
                        'consumers']

    @classmethod
    def get_secret_list(cls, external_project_id,
                        offset_arg=None, limit_arg=None,
                        name=None, alg=None, mode=None,
                        bits=0, secret_type=None, suppress_exception=False,
                        session=None, acl_only=None, user_id=None,
                        created=None, updated=None, expiration=None,
                        sort=None):
        secrets_db, offset, limit, total = cls.db_repo.get_secret_list(
            external_project_id, offset_arg, limit_arg, name, alg, mode, bits,
            secret_type, suppress_exception, session, acl_only, user_id,
            created, updated, expiration, sort)
        secrets_object = [cls()._from_db_object(secret_db)
                          for secret_db in secrets_db]
        return secrets_object, offset, limit, total

    @classmethod
    def get_secret_by_id(cls, entity_id, suppress_exception=False,
                         session=None):
        secret_db = cls.db_repo.get_secret_by_id(
            entity_id, suppress_exception, session)
        return cls()._from_db_object(secret_db)
