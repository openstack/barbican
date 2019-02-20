"""
Copyright 2014-2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging
from oslo_serialization import jsonutils as json

LOG = logging.getLogger(__name__)


class BaseModel(object):
    """Base class for models.

    To allow simple (de)serialization we will use __dict__ to create
    """
    def override_values(self, **kwargs):
        for attr_name, attr_value in kwargs.items():
            if hasattr(self, attr_name):
                setattr(self, attr_name, attr_value)

    def obj_to_json(self):
        """Convert this object to a JSON string.

        :return: A string of JSON containing the fields in this object
        """
        return json.dump_as_bytes(self.obj_to_dict())

    def obj_to_dict(self):
        """Create a dict of the values for this model object.

        If there are  fields that are not set in this object then those
        will NOT have entries in the returned dict.

        :return: A dict representing this model
        """
        the_dict = self.__dict__
        retval = self._remove_empty_fields_from_dict(the_dict)
        return retval

    def _remove_empty_fields_from_dict(self, dictionary):
        """Remove k,v pairs with empty values from a dictionary.

        :param dictionary: a dictionary of stuff
        :return: the same dictionary where all k,v pairs with empty values
        have been removed.
        """

        # NOTE(jaosorior): deleting a key from the incoming dictionary actually
        # affects the model object. So we do a copy to avoid this.
        resulting_dict = dictionary.copy()

        # Dumping the keys to a list as we'll be changing the dict size
        empty_keys = [k for k, v in dictionary.items() if v is None]
        for k in empty_keys:
            del resulting_dict[k]
        return resulting_dict

    @classmethod
    def json_to_obj(cls, serialized_str):
        """Create a model from a JSON string.

        :param serialized_str: the JSON string
        :return: a secret object
        """
        try:
            json_dict = json.loads(serialized_str)
            return cls.dict_to_obj(json_dict)
        except TypeError as e:
            LOG.error('Couldn\'t deserialize input: %s\n Because: %s',
                      serialized_str, e)

    @classmethod
    def dict_to_obj(cls, input_dict):
        """Create an object from a dict.

        :param input_dict: A dict of fields.
        :return: a model object build from the passed in dict.
        """
        return cls(**input_dict)
