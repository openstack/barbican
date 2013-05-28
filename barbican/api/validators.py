"""
API JSON validators.
"""

import abc
import dateutil.parser
from jsonschema import validate, ValidationError
from barbican.common import exception
from barbican.openstack.common import timeutils
from barbican.common import utils


LOG = utils.getLogger(__name__)
DEFAULT_SECRET_NAME = 'unknown'


class ValidatorBase(object):
    """Base class for validators."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def validate(self, json_data):
        """Validate the input JSON.

        :param json_data: JSON to validate against this class' internal schema.
        :returns: dict -- JSON content, post-validation and normalization/defaulting.
        :raises: ValidationError on schema violations.

        """


class NewSecretValidator(ValidatorBase):
    """Validate a new secret."""

    def __init__(self):
        self.name = 'Secret'
        self.schema = {
            "type" : "object",
            "properties" : {
                "name" : {"type" : "string"},
                "algorithm" : {"type" : "string"},
                "cypher_type": {"type" : "string"},
                "bit_length": {"type": "integer", "minimum": 0},
                "expiration" : {"type" : "string"},
                "plain_text" : {"type" : "string"},
                "mime_type" : {"type" : "string"},
            },
            "required": ["mime_type"]
        }

    def validate(self, json_data):
        try:
            validate(json_data, self.schema)
        except ValidationError as e:
            raise exception.InvalidObject(schema=self.name, reason=str(e))

        # Validate/normalize 'name'.
        name = json_data.get('name', DEFAULT_SECRET_NAME).strip()
        if not name:
            name = DEFAULT_SECRET_NAME
        json_data['name'] = name

        # Validate/convert 'expiration' if provided.
        expiration = self._extract_expiration(json_data)
        if expiration:
            try:
                expiration = dateutil.parser.parse(expiration)                
            except ValueError:
                LOG.exception("Problem parsing date")
                raise exception.InvalidObject(schema=self.name,
                                              reason=_("Invalid date '"
                                                       "for 'expiration'"))
            # Verify not already expired.
            utcnow = timeutils.utcnow()
            if expiration <= utcnow:
                raise exception.InvalidObject(schema=self.name,
                                              reason=_("'expiration' is "
                                                       "before current time"))             
        json_data['expiration'] = expiration

        # Validate/convert 'plain_text' if provided.
        if 'plain_text' in json_data:
            plain_text = json_data['plain_text'].strip()
            if not plain_text:
                raise exception.InvalidObject(schema=self.name,
                                              reason=_('If plain_text '
                                                       'specified, must be '
                                                       'non empty'))
            json_data['plain_text'] = plain_text

        # TODO: Add validation of 'mime_type' based on loaded plugins.

        return json_data

    def _extract_expiration(self, json_data):
        """Extracts and returns the expiration date from the JSON data."""
        expiration = json_data.get('expiration', None)
        if expiration:
            if not expiration.strip():
                expiration = None
        return expiration
