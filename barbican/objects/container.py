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
from barbican.objects import container_secret as con_se
from barbican.objects import fields

TYPE_VALUE = ['generic', 'rsa', 'dsa', 'certificate']


@object_base.VersionedObjectRegistry.register
class Container(base.BarbicanObject, base.BarbicanPersistentObject,
                object_base.VersionedObjectDictCompat):
    fields = {
        'name': fields.StringField(nullable=True, default=None),
        'type': fields.EnumField(nullable=True, valid_values=TYPE_VALUE),
        'project_id': fields.StringField(nullable=True, default=None),
        'creator_id': fields.StringField(nullable=True, default=None),
        'consumers': fields.ListOfObjectsField('ContainerConsumerMetadatum',
                                               default=list()),
        'container_secrets': fields.ListOfObjectsField('ContainerSecret',
                                                       default=list()),
        'container_acls': fields.ListOfObjectsField('ContainerACL',
                                                    default=list()),
        'project': fields.ObjectField('Project', nullable=True, default=None)
    }

    db_model = models.Container
    db_repo = repos.get_container_repository()
    synthetic_fields = ['consumers', 'container_secrets',
                        'container_acls', 'project']

    def __init__(self, context=None, parsed_request=None, **kwargs):
        super(Container, self).__init__(context=context, **kwargs)
        if parsed_request:
            self.name = parsed_request.get('name')
            self.type = parsed_request.get('type')
            self.status = base.States.ACTIVE
            self.creator_id = parsed_request.get('creator_id')

            secret_refs = parsed_request.get('secret_refs')
            if secret_refs:
                for secret_ref in parsed_request.get('secret_refs'):
                    container_secret = con_se.ContainerSecret()
                    container_secret.name = secret_ref.get('name')
                    secret_id = secret_ref.get('secret_ref')
                    if secret_id.endswith('/'):
                        secret_id = secret_id.rsplit('/', 2)[1]
                    elif '/' in secret_id:
                        secret_id = secret_id.rsplit('/', 1)[1]
                    else:
                        secret_id = secret_id
                    container_secret.secret_id = secret_id
                    self.container_secrets.append(container_secret)

    def _get_db_entity(self, data=None):
        return self.db_model(parsed_request=data, check_exc=False)

    def _attach_container_secret(self, container_secrets, container_id,
                                 session):
        if container_secrets:
            for container_secret in container_secrets:
                container_secret.container_id = container_id
                if container_secret.id is None:
                    self.container_secrets.append(container_secret.create(
                        session=session))
                else:
                    self.container_secrets.append(container_secret.save(
                        session=session))

    def _attach_consumers(self, consumers, container_id, session):
        if consumers:
            for consumer in consumers:
                consumer.container_id = container_id
                if consumer.id is None:
                    self.consumers.append(consumer.create(session=session))
                else:
                    self.consumers.append(consumer.save(session=session))

    def create(self, session=None):
        fields = self.obj_get_changes()
        super(Container, self).create(session=session)
        if 'container_secrets' in fields:
            self._attach_container_secret(
                fields['container_secrets'],
                container_id=self.id, session=session)
        if 'consumers' in fields:
            self._attach_consumers(fields['consumers'],
                                   container_id=self.id, session=session)

    def save(self, session=None):
        fields = self.obj_get_changes()
        super(Container, self).save(session=session)
        if 'consumers' in fields:
            self._attach_consumers(fields['consumers'],
                                   container_id=self.id, session=session)

    @classmethod
    def get_by_create_date(cls, external_project_id, offset_arg=None,
                           limit_arg=None, name_arg=None,
                           suppress_exception=False, session=None):
        entities_db, offset, limit, total = cls.db_repo.get_by_create_date(
            external_project_id, offset_arg, limit_arg, name_arg,
            suppress_exception, session
        )
        entities_obj = [cls()._from_db_object(entity_db)
                        for entity_db in entities_db]
        return entities_obj, offset, limit, total

    @classmethod
    def get_container_by_id(cls, entity_id, suppress_exception=False,
                            session=None):
        entity_db = cls.db_repo.get_container_by_id(entity_id,
                                                    suppress_exception,
                                                    session)
        return cls()._from_db_object(entity_db)
