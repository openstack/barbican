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
"""Barbican common internal objects model"""

from oslo_versionedobjects import base as object_base

from barbican.model import repositories as repos
from barbican.objects import fields


class States(object):
    PENDING = 'PENDING'
    ACTIVE = 'ACTIVE'
    ERROR = 'ERROR'

    @classmethod
    def is_valid(cls, state_to_test):
        """Tests if a state is a valid one."""
        return state_to_test in cls.__dict__


class BarbicanPersistentObject(object):
    fields = {
        'id': fields.StringField(nullable=True, default=None),
        'created_at': fields.DateTimeField(nullable=True, tzinfo_aware=False),
        'updated_at': fields.DateTimeField(nullable=True, tzinfo_aware=False),
        'deleted_at': fields.DateTimeField(nullable=True, tzinfo_aware=False),
        'deleted': fields.BooleanField(nullable=True),
        'status': fields.StringField(nullable=True, default=States.PENDING)
    }


class BarbicanObject(object_base.VersionedObject):

    # Version 1.0: Initial version
    VERSION = '1.0'

    OBJ_PROJECT_NAMESPACE = 'barbican'
    synthetic_fields = []

    # NOTE(namnh): The db_model, db_repo class variable should be inherited
    # by sub-classes.
    # For example, in the Secret object has to have "db_model = models.Secret"
    # and "db_repo = repo.get_secret_repository()".
    db_model = None
    db_repo = repos.BaseRepo()

    def __init__(self, context=None, **kwargs):
        super(BarbicanObject, self).__init__(context=context, **kwargs)
        self.dict_fields = None
        self.obj_set_defaults()

    def set_attribute(self, name_attr, value_attr=None):
        setattr(self, name_attr, value_attr)

    def _get_db_entity(self):
        return self.db_model(check_exc=False)

    def _get_changed_persistent_fields(self):
        change_fields = self.obj_get_changes()
        for field in self.synthetic_fields:
            if field in change_fields:
                del change_fields[field]
        return change_fields

    def _validate_fields(self, change_fields):
        """Validate fields before creating model

        In order to verify fields before saving a model to database. It should
        be inherited by sub-class in case the class need to verify.
        """
        pass

    def _from_db_object(self, db_entity):
        if db_entity is None:
            return None
        for field in self.fields:
            if field not in self.synthetic_fields:
                self.set_attribute(field, db_entity[field])
        self.load_synthetic_db_fields(db_entity=db_entity)
        self.dict_fields = db_entity.to_dict_fields()
        self.obj_reset_changes()
        return self

    def to_dict_fields(self):
        return self.dict_fields

    def register_value(self, data=None, **kwargs):
        data = data or dict()
        data.update(kwargs)
        for key, value in data.items():
            setattr(self, key, value)

    @classmethod
    def is_synthetic(cls, field):
        return field in cls.synthetic_fields

    @classmethod
    def load_object(cls, db_entity):
        obj = cls()
        obj._from_db_object(db_entity=db_entity)
        return obj

    def load_synthetic_db_fields(self, db_entity):
        """Load synthetic database field.

        :param db_entity: Database model
        :return: None
        """
        for field in self.synthetic_fields:
            objclasses = object_base.VersionedObjectRegistry.obj_classes(
            ).get(self.fields[field].objname)

            objclass = objclasses[0]
            synth_db_objs = db_entity.get(field, None)

            # NOTE(namnh): synth_db_objs can be list, dict, empty list
            if isinstance(self.fields[field], fields.DictOfObjectsField):
                dict_entity_object = {key: objclass.load_object(value)
                                      for key, value in synth_db_objs.items()}
                setattr(self, field, dict_entity_object)
            elif isinstance(self.fields[field], fields.ListOfObjectsField):
                entities_object = [objclass.load_object(entity)
                                   for entity in synth_db_objs]
                setattr(self, field, entities_object)
            else:
                # At this moment, this field is an ObjectField.
                entity_object = objclass.load_object(synth_db_objs)
                setattr(self, field, entity_object)
            self.obj_reset_changes([fields])

    def create(self, session=None):
        change_fields = self._get_changed_persistent_fields()
        self._validate_fields(change_fields)
        db_entity = self._get_db_entity()
        db_entity.update(change_fields)
        db_entity = self.db_repo.create_from(db_entity, session=session)
        self._from_db_object(db_entity)

    def save(self, session=None):
        """To update new values to a row in database."""
        change_fields = self._get_changed_persistent_fields()
        self.db_repo.update_from(self.db_model, self.id,
                                 change_fields, session=session)
        self.obj_reset_changes()

    def delete(self, session):
        raise NotImplementedError()

    @classmethod
    def get(cls, entity_id, external_project_id=None,
            force_show_deleted=False,
            suppress_exception=False, session=None):
        """Get an entity or raise if it does not exist"""
        db_entity = cls.db_repo.get(
            entity_id, external_project_id=external_project_id,
            force_show_deleted=force_show_deleted,
            suppress_exception=suppress_exception, session=session)
        if db_entity:
            return cls()._from_db_object(db_entity)
        else:
            return None

    @classmethod
    def get_session(cls, session=None):
        return session or repos.get_session()

    @classmethod
    def delete_entity_by_id(cls, entity_id, external_project_id,
                            session=None):
        cls.db_repo.delete_entity_by_id(
            entity_id, external_project_id, session=session)

    @classmethod
    def get_project_entities(cls, project_id, session=None):
        """Gets entities associated with a given project."""
        entities_db = cls.db_repo.get_project_entities(project_id,
                                                       session=session)
        entities_object = [cls()._from_db_object(entity_db)
                           for entity_db in entities_db] if entities_db else []
        return entities_object

    @classmethod
    def get_count(cls, project_id, session=None):
        """Gets count of entities associated with a given project"""
        return cls.db_repo.get_count(project_id, session=session)

    @classmethod
    def delete_project_entities(cls, project_id,
                                suppress_exception=False,
                                session=None):
        """Deletes entities for a given project."""
        cls.db_repo.delete_project_entities(
            project_id, suppress_exception=suppress_exception, session=session)
