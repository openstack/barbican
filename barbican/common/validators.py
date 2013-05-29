"""
API JSON validators.
"""

import abc
import dateutil.parser
from jsonschema import validate, ValidationError
from oslo.config import cfg
from barbican.common import exception
from barbican.openstack.common import timeutils
from barbican.common import utils


LOG = utils.getLogger(__name__)
DEFAULT_MAX_SECRET_BYTES = 10000
common_opts = [
    cfg.IntOpt('max_allowed_secret_in_bytes',
               default=DEFAULT_MAX_SECRET_BYTES),
]

CONF = cfg.CONF
CONF.register_opts(common_opts)


def secret_too_big(data):
    return len(data.encode('utf-8')) > CONF.max_allowed_secret_in_bytes


class ValidatorBase(object):
    """Base class for validators."""

    __metaclass__ = abc.ABCMeta
    name = ''

    @abc.abstractmethod
    def validate(self, json_data, parent_schema=None):
        """Validate the input JSON.

        :param json_data: JSON to validate against this class' internal schema.
        :param parent_schema: Name of the parent schema to this schema.
        :returns: dict -- JSON content, post-validation and
        :                 normalization/defaulting.
        :raises: ValidationError on schema violations.

        """

    def _full_name(self, parent_schema=None):
        """
        Returns the full schema name for this validator,
        including parent name.
        """
        schema_name = self.name
        if parent_schema:
            schema_name = _("{0}' within '{1}").format(self.name, parent_schema)
        return schema_name


class NewSecretValidator(ValidatorBase):
    """Validate a new secret."""

    def __init__(self):
        self.name = 'Secret'
        self.schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "algorithm": {"type": "string"},
                "cypher_type": {"type": "string"},
                "bit_length": {"type": "integer", "minimum": 0},
                "expiration": {"type": "string"},
                "plain_text": {"type": "string"},
                "mime_type": {"type": "string"},
            },
            "required": ["mime_type"]
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        try:
            validate(json_data, self.schema)
        except ValidationError as e:
            raise exception.InvalidObject(schema=schema_name, reason=str(e))

        # Validate/normalize 'name'.
        name = json_data.get('name', '').strip()
        if not name:
            name = None
        json_data['name'] = name

        # Validate/convert 'expiration' if provided.
        expiration = self._extract_expiration(json_data)
        if expiration:
            try:
                expiration = dateutil.parser.parse(expiration)
            except ValueError:
                LOG.exception("Problem parsing date")
                raise exception.InvalidObject(schema=schema_name,
                                              reason=_("Invalid date "
                                                       "for 'expiration'"))
            # Verify not already expired.
            utcnow = timeutils.utcnow()
            if expiration <= utcnow:
                raise exception.InvalidObject(schema=schema_name,
                                              reason=_("'expiration' is "
                                                       "before current time"))
        json_data['expiration'] = expiration

        # Validate/convert 'plain_text' if provided.
        if 'plain_text' in json_data:

            plain_text = json_data['plain_text']
            if secret_too_big(plain_text):
                raise exception.LimitExceeded()

            plain_text = plain_text.strip()
            if not plain_text:
                raise exception.InvalidObject(schema=schema_name,
                                              reason=_("If 'plain_text' "
                                                       "specified, must be "
                                                       "non empty"))
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


class NewOrderValidator(ValidatorBase):
    """Validate a new order."""

    def __init__(self):
        self.name = 'Order'
        self.schema = {
            "type": "object",
            "properties": {
            },
        }
        self.secret_validator = NewSecretValidator()

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        try:
            validate(json_data, self.schema)
        except ValidationError as e:
            raise exception.InvalidObject(schema=schema_name, reason=str(e))

        # If secret group is provided, validate it now.
        if 'secret' in json_data:
            secret = json_data['secret']
            self.secret_validator.validate(secret, parent_schema=self.name)
            if 'plain_text' in secret:
                raise exception.InvalidObject(schema=schema_name,
                                              reason=_("'plain_text' not "
                                                       "allowed for secret "
                                                       "generation"))
        else:
            raise exception.InvalidObject(schema=schema_name,
                                          reason=_("'secret' attributes "
                                                   "are required"))

        return json_data
