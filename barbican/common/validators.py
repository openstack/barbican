#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
API JSON validators.
"""

import abc
import base64
import re

import jsonschema as schema
from ldap3.core import exceptions as ldap_exceptions
from ldap3.utils.dn import parse_dn
from OpenSSL import crypto
from oslo_utils import timeutils

from barbican.api import controllers
from barbican.common import config
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.plugin.interface import secret_store
from barbican.plugin.util import mime_types


DEFAULT_MAX_SECRET_BYTES = config.DEFAULT_MAX_SECRET_BYTES
LOG = utils.getLogger(__name__)
CONF = config.CONF

MYSQL_SMALL_INT_MAX = 32767

ACL_OPERATIONS = ['read', 'write', 'delete', 'list']


def secret_too_big(data):
    if isinstance(data, str):
        return len(data.encode('UTF-8')) > CONF.max_allowed_secret_in_bytes
    else:
        return len(data) > CONF.max_allowed_secret_in_bytes


def get_invalid_property(validation_error):
    # we are interested in the second item which is the failed propertyName.
    if validation_error.schema_path and len(validation_error.schema_path) > 1:
        return validation_error.schema_path[1]


def validate_stored_key_rsa_container(project_id, container_ref, req):
    try:
        container_id = hrefs.get_container_id_from_ref(container_ref)
    except Exception:
        reason = u._("Bad Container Reference {ref}").format(
            ref=container_ref
        )
        raise exception.InvalidContainer(reason=reason)

    container_repo = repo.get_container_repository()

    container = container_repo.get_container_by_id(entity_id=container_id,
                                                   suppress_exception=True)
    if not container:
        reason = u._("Container Not Found")
        raise exception.InvalidContainer(reason=reason)

    if container.type != 'rsa':
        reason = u._("Container Wrong Type")
        raise exception.InvalidContainer(reason=reason)

    ctxt = controllers._get_barbican_context(req)
    inst = controllers.containers.ContainerController(container)
    controllers._do_enforce_rbac(inst, req,
                                 controllers.containers.CONTAINER_GET,
                                 ctxt)


class ValidatorBase(object, metaclass=abc.ABCMeta):
    """Base class for validators."""

    name = ''

    @abc.abstractmethod
    def validate(self, json_data, parent_schema=None):
        """Validate the input JSON.

        :param json_data: JSON to validate against this class' internal schema.
        :param parent_schema: Name of the parent schema to this schema.
        :returns: dict -- JSON content, post-validation and
        :                 normalization/defaulting.
        :raises: schema.ValidationError on schema violations.

        """

    def _full_name(self, parent_schema=None):
        """Validator schema name accessor

        Returns the full schema name for this validator,
        including parent name.
        """
        schema_name = self.name
        if parent_schema:
            schema_name = u._(
                "{schema_name}' within '{parent_schema_name}").format(
                    schema_name=self.name,
                    parent_schema_name=parent_schema)
        return schema_name

    def _assert_schema_is_valid(self, json_data, schema_name):
        """Assert that the JSON structure is valid for the given schema.

        :raises: InvalidObject exception if the data is not schema compliant.
        """
        try:
            schema.validate(json_data, self.schema)
        except schema.ValidationError as e:
            raise exception.InvalidObject(schema=schema_name,
                                          reason=e.message,
                                          property=get_invalid_property(e))

    def _assert_validity(self, valid_condition, schema_name, message,
                         property):
        """Assert that a certain condition is met.

        :raises: InvalidObject exception if the condition is not met.
        """
        if not valid_condition:
            raise exception.InvalidObject(schema=schema_name, reason=message,
                                          property=property)


class NewSecretValidator(ValidatorBase):
    """Validate a new secret."""

    def __init__(self):
        self.name = 'Secret'

        # TODO(jfwood): Get the list of mime_types from the crypto plugins?
        self.schema = {
            "type": "object",
            "properties": {
                "name": {"type": ["string", "null"], "maxLength": 255},
                "algorithm": {"type": "string", "maxLength": 255},
                "mode": {"type": "string", "maxLength": 255},
                "bit_length": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MYSQL_SMALL_INT_MAX
                },
                "expiration": {"type": "string", "maxLength": 255},
                "payload": {"type": "string"},
                "secret_type": {
                    "type": "string",
                    "maxLength": 80,
                    "enum": [secret_store.SecretType.SYMMETRIC,
                             secret_store.SecretType.PASSPHRASE,
                             secret_store.SecretType.PRIVATE,
                             secret_store.SecretType.PUBLIC,
                             secret_store.SecretType.CERTIFICATE,
                             secret_store.SecretType.OPAQUE]
                },
                "payload_content_type": {
                    "type": ["string", "null"],
                    "maxLength": 255
                },
                "payload_content_encoding": {
                    "type": "string",
                    "maxLength": 255,
                    "enum": [
                        "base64"
                    ]
                },
                "transport_key_needed": {
                    "type": "string",
                    "enum": ["true", "false"]
                },
                "transport_key_id": {"type": "string"},
            },
        }

    def validate(self, json_data, parent_schema=None):
        """Validate the input JSON for the schema for secrets."""
        schema_name = self._full_name(parent_schema)
        self._assert_schema_is_valid(json_data, schema_name)

        json_data['name'] = self._extract_name(json_data)

        expiration = self._extract_expiration(json_data, schema_name)
        self._assert_expiration_is_valid(expiration, schema_name)
        json_data['expiration'] = expiration
        content_type = json_data.get('payload_content_type')

        if 'payload' in json_data:
            content_encoding = json_data.get('payload_content_encoding')
            self._validate_content_parameters(content_type, content_encoding,
                                              schema_name)

            payload = self._extract_payload(json_data)
            self._assert_validity(payload, schema_name,
                                  u._("If 'payload' specified, must be non "
                                      "empty"),
                                  "payload")
            self._validate_payload_by_content_encoding(content_encoding,
                                                       payload, schema_name)
            json_data['payload'] = payload
        elif 'payload_content_type' in json_data:
            # parent_schema would be populated if it comes from an order.
            self._assert_validity(parent_schema is not None, schema_name,
                                  u._("payload must be provided when "
                                      "payload_content_type is specified"),
                                  "payload")

            if content_type:
                self._assert_validity(
                    mime_types.is_supported(content_type),
                    schema_name,
                    u._("payload_content_type is not one of {supported}"
                        ).format(supported=mime_types.SUPPORTED),
                    "payload_content_type")

        return json_data

    def _extract_name(self, json_data):
        """Extracts and returns the name from the JSON data."""
        name = json_data.get('name')
        if isinstance(name, str):
            return name.strip()
        return None

    def _extract_expiration(self, json_data, schema_name):
        """Extracts and returns the expiration date from the JSON data."""
        expiration = None
        expiration_raw = json_data.get('expiration')
        if expiration_raw and expiration_raw.strip():
            try:
                expiration_tz = timeutils.parse_isotime(expiration_raw.strip())
                expiration = timeutils.normalize_time(expiration_tz)
            except ValueError:
                LOG.exception("Problem parsing expiration date")
                raise exception.InvalidObject(
                    schema=schema_name,
                    reason=u._("Invalid date for 'expiration'"),
                    property="expiration")

        return expiration

    def _assert_expiration_is_valid(self, expiration, schema_name):
        """Asserts that the given expiration date is valid.

        Expiration dates must be in the future, not the past.
        """
        if expiration:
            # Verify not already expired.
            utcnow = timeutils.utcnow()
            self._assert_validity(expiration > utcnow, schema_name,
                                  u._("'expiration' is before current time"),
                                  "expiration")

    def _validate_content_parameters(self, content_type, content_encoding,
                                     schema_name):
        """Content parameter validator.

        Check that the content_type, content_encoding and the parameters
        that they affect are valid.
        """
        self._assert_validity(
            content_type is not None,
            schema_name,
            u._("If 'payload' is supplied, 'payload_content_type' must also "
                "be supplied."),
            "payload_content_type")

        self._assert_validity(
            mime_types.is_supported(content_type),
            schema_name,
            u._("payload_content_type is not one of {supported}"
                ).format(supported=mime_types.SUPPORTED),
            "payload_content_type")

        self._assert_validity(
            mime_types.is_content_type_with_encoding_supported(
                content_type,
                content_encoding),
            schema_name,
            u._("payload_content_encoding is not one of {supported}").format(
                supported=mime_types.get_supported_encodings(content_type)),
            "payload_content_encoding")

    def _validate_payload_by_content_encoding(self, payload_content_encoding,
                                              payload, schema_name):
        if payload_content_encoding == 'base64':
            try:
                base64.b64decode(payload)
            except Exception:
                LOG.exception("Problem parsing payload")
                raise exception.InvalidObject(
                    schema=schema_name,
                    reason=u._("Invalid payload for payload_content_encoding"),
                    property="payload")

    def _extract_payload(self, json_data):
        """Extracts and returns the payload from the JSON data.

        :raises: LimitExceeded if the payload is too big
        """
        payload = json_data.get('payload', '')
        if secret_too_big(payload):
            raise exception.LimitExceeded()

        return payload.strip()


class NewSecretMetadataValidator(ValidatorBase):
    """Validate new secret metadata."""

    def __init__(self):
        self.name = 'SecretMetadata'
        self.schema = {
            "type": "object",
            "$schema": "http://json-schema.org/draft-03/schema",
            "properties": {
                "metadata": {"type": "object", "required": True},
            }
        }

    def validate(self, json_data, parent_schema=None):
        """Validate the input JSON for the schema for secret metadata."""
        schema_name = self._full_name(parent_schema)
        self._assert_schema_is_valid(json_data, schema_name)
        return self._extract_metadata(json_data)

    def _extract_metadata(self, json_data):
        """Extracts and returns the metadata from the JSON data."""
        metadata = json_data['metadata']

        for key in list(metadata):
            # make sure key is a string and url-safe.
            if not isinstance(key, str):
                raise exception.InvalidMetadataRequest()
            self._check_string_url_safe(key)

            # make sure value is a string.
            value = metadata[key]
            if not isinstance(value, str):
                raise exception.InvalidMetadataRequest()

            # If key is not lowercase, then change it
            if not key.islower():
                del metadata[key]
                metadata[key.lower()] = value

        return metadata

    def _check_string_url_safe(self, string):
        """Checks if string can be part of a URL."""
        if not re.match("^[A-Za-z0-9_-]*$", string):
            raise exception.InvalidMetadataKey()


class NewSecretMetadatumValidator(ValidatorBase):
    """Validate new secret metadatum."""

    def __init__(self):
        self.name = 'SecretMetadatum'
        self.schema = {
            "type": "object",
            "$schema": "http://json-schema.org/draft-03/schema",
            "properties": {
                "key": {
                    "type": "string",
                    "maxLength": 255,
                    "required": True
                },
                "value": {
                    "type": "string",
                    "maxLength": 255,
                    "required": True
                },
            },
            "additionalProperties": False
        }

    def validate(self, json_data, parent_schema=None):
        """Validate the input JSON for the schema for secret metadata."""
        schema_name = self._full_name(parent_schema)
        self._assert_schema_is_valid(json_data, schema_name)

        key = self._extract_key(json_data)
        value = self._extract_value(json_data)

        return {"key": key, "value": value}

    def _extract_key(self, json_data):
        """Extracts and returns the metadata from the JSON data."""
        key = json_data['key']
        self._check_string_url_safe(key)
        key = key.lower()
        return key

    def _extract_value(self, json_data):
        """Extracts and returns the metadata from the JSON data."""
        value = json_data['value']
        return value

    def _check_string_url_safe(self, string):
        """Checks if string can be part of a URL."""
        if not re.match("^[A-Za-z0-9_-]*$", string):
            raise exception.InvalidMetadataKey()


class CACommonHelpersMixin(object):
    def _validate_subject_dn_data(self, subject_dn):
        """Confirm that the subject_dn contains valid data

        Validate that the subject_dn string parses without error
        If not, raise InvalidSubjectDN
        """
        try:
            parse_dn(subject_dn)
        except ldap_exceptions.LDAPInvalidDnError:
            raise exception.InvalidSubjectDN(subject_dn=subject_dn)


# TODO(atiwari) - Split this validator module and unit tests
# into smaller modules
class TypeOrderValidator(ValidatorBase, CACommonHelpersMixin):
    """Validate a new typed order."""

    def __init__(self):
        self.name = 'Order'
        self.schema = {
            "type": "object",
            "$schema": "http://json-schema.org/draft-03/schema",
            "properties": {
                "meta": {
                    "type": "object",
                    "required": True
                },
                "type": {
                    "type": "string",
                    "required": True,
                    "enum": ['key', 'asymmetric', 'certificate']
                }
            }
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        order_type = json_data.get('type').lower()

        if order_type == models.OrderType.CERTIFICATE:
            certificate_meta = json_data.get('meta')
            self._validate_certificate_meta(certificate_meta, schema_name)

        elif order_type == models.OrderType.ASYMMETRIC:
            asymmetric_meta = json_data.get('meta')
            self._validate_asymmetric_meta(asymmetric_meta, schema_name)

        elif order_type == models.OrderType.KEY:
            key_meta = json_data.get('meta')
            self._validate_key_meta(key_meta, schema_name)

        else:
            self._raise_feature_not_implemented(order_type, schema_name)

        return json_data

    def _validate_key_meta(self, key_meta, schema_name):
        """Validation specific to meta for key type order."""

        secret_validator = NewSecretValidator()
        secret_validator.validate(key_meta, parent_schema=self.name)

        self._assert_validity(key_meta.get('payload') is None,
                              schema_name,
                              u._("'payload' not allowed "
                                  "for key type order"), "meta")

        # Validation secret generation related fields.
        # TODO(jfwood): Invoke the crypto plugin for this purpose

        self._validate_meta_parameters(key_meta, "key", schema_name)

    def _validate_asymmetric_meta(self, asymmetric_meta, schema_name):
        """Validation specific to meta for asymmetric type order."""

        # Validate secret metadata.
        secret_validator = NewSecretValidator()
        secret_validator.validate(asymmetric_meta, parent_schema=self.name)

        self._assert_validity(asymmetric_meta.get('payload') is None,
                              schema_name,
                              u._("'payload' not allowed "
                                  "for asymmetric type order"), "meta")

        self._validate_meta_parameters(asymmetric_meta, "asymmetric key",
                                       schema_name)

    def _get_required_metadata_value(self, metadata, key):
        data = metadata.get(key, None)
        if data is None:
            raise exception.MissingMetadataField(required=key)
        return data

    def _validate_certificate_meta(self, certificate_meta, schema_name):
        """Validation specific to meta for certificate type order."""

        self._assert_validity(certificate_meta.get('payload') is None,
                              schema_name,
                              u._("'payload' not allowed "
                                  "for certificate type order"), "meta")

        if 'profile' in certificate_meta:
            if 'ca_id' not in certificate_meta:
                raise exception.MissingMetadataField(required='ca_id')

        jump_table = {
            'simple-cmc': self._validate_simple_cmc_request,
            'full-cmc': self._validate_full_cmc_request,
            'stored-key': self._validate_stored_key_request,
            'custom': self._validate_custom_request
        }

        request_type = certificate_meta.get("request_type", "custom")
        if request_type not in jump_table:
            raise exception.InvalidCertificateRequestType(request_type)

        jump_table[request_type](certificate_meta)

    def _validate_simple_cmc_request(self, certificate_meta):
        """Validates simple CMC (which are PKCS10 requests)."""
        request_data = self._get_required_metadata_value(
            certificate_meta, "request_data")
        self._validate_pkcs10_data(request_data)

    def _validate_full_cmc_request(self, certificate_meta):
        """Validate full CMC request.

        :param certificate_meta: request data from the order
        :raises: FullCMCNotSupported
        """
        raise exception.FullCMCNotSupported()

    def _validate_stored_key_request(self, certificate_meta):
        """Validate stored-key cert request."""
        self._get_required_metadata_value(
            certificate_meta, "container_ref")
        subject_dn = self._get_required_metadata_value(
            certificate_meta, "subject_dn")
        self._validate_subject_dn_data(subject_dn)
        # container will be validated by validate_stored_key_rsa_container()

        extensions = certificate_meta.get("extensions", None)
        if extensions:
            self._validate_extensions_data(extensions)

    def _validate_custom_request(self, certificate_meta):
        """Validate custom data request

        We cannot do any validation here because the request
        parameters are custom.  Validation will be done by the
        plugin.  We may choose to select the relevant plugin and
        call the supports() method to raise validation errors.
        """
        pass

    def _validate_pkcs10_data(self, request_data):
        """Confirm that the request_data is valid base64 encoded PKCS#10.

        Base64 decode the request, if it fails raise PayloadDecodingError.
        Then parse data into the ASN.1 structure defined by PKCS10 and
        verify the signing information.
        If parsing of verifying fails, raise InvalidPKCS10Data.
        """
        try:
            csr_pem = base64.b64decode(request_data)
        except Exception:
            raise exception.PayloadDecodingError()

        try:
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,
                                                  csr_pem)
        except Exception:
            reason = u._("Bad format")
            raise exception.InvalidPKCS10Data(reason=reason)

        try:
            pubkey = csr.get_pubkey()
            csr.verify(pubkey)
        except Exception:
            reason = u._("Signing key incorrect")
            raise exception.InvalidPKCS10Data(reason=reason)

    def _validate_full_cmc_data(self, request_data):
        """Confirm that request_data is valid Full CMC data."""
        """
        TODO(alee-3) complete this function

        Parse data into the ASN.1 structure defined for full CMC.
        If parsing fails, raise InvalidCMCData
        """
        pass

    def _validate_extensions_data(self, extensions):
        """Confirm that the extensions data is valid.

        :param extensions: base 64 encoded ASN.1 string of extension data
        :raises: CertificateExtensionsNotSupported
        """
        """
        TODO(alee-3) complete this function

        Parse the extensions data into the correct ASN.1 structure.
        If the parsing fails, throw InvalidExtensionsData.

        For now, fail this validation because extensions parsing is not
        supported.
        """
        raise exception.CertificateExtensionsNotSupported()

    def _validate_meta_parameters(self, meta, order_type, schema_name):
        self._assert_validity(meta.get('algorithm'),
                              schema_name,
                              u._("'algorithm' is required field "
                                  "for {0} type order").format(order_type),
                              "meta")

        self._assert_validity(meta.get('bit_length'),
                              schema_name,
                              u._("'bit_length' is required field "
                                  "for {0} type order").format(order_type),
                              "meta")

        self._validate_bit_length(meta, schema_name)

    def _extract_expiration(self, json_data, schema_name):
        """Extracts and returns the expiration date from the JSON data."""
        expiration = None
        expiration_raw = json_data.get('expiration', None)
        if expiration_raw and expiration_raw.strip():
            try:
                expiration_tz = timeutils.parse_isotime(expiration_raw)
                expiration = timeutils.normalize_time(expiration_tz)
            except ValueError:
                LOG.exception("Problem parsing expiration date")
                raise exception.InvalidObject(schema=schema_name,
                                              reason=u._("Invalid date "
                                                         "for 'expiration'"),
                                              property="expiration")

        return expiration

    def _validate_bit_length(self, meta, schema_name):

        bit_length = int(meta.get('bit_length'))
        if bit_length % 8 != 0:
            raise exception.UnsupportedField(field="bit_length",
                                             schema=schema_name,
                                             reason=u._("Must be a"
                                                        " positive integer"
                                                        " that is a"
                                                        " multiple of 8"))

    def _raise_feature_not_implemented(self, order_type, schema_name):
        raise exception.FeatureNotImplemented(field='type',
                                              schema=schema_name,
                                              reason=u._("Feature not "
                                                         "implemented for "
                                                         "'{0}' order type")
                                                    .format(order_type))


class ACLValidator(ValidatorBase):
    """Validate ACL(s)."""

    def __init__(self):
        self.name = 'ACL'

        self.schema = {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "definitions": {
                "acl_defintion": {
                    "type": "object",
                    "properties": {
                        "users": {
                            "type": "array",
                            "items": [
                                {"type": "string", "maxLength": 255}
                            ]
                        },
                        "project-access": {"type": "boolean"}
                    },
                    "additionalProperties": False
                }
            },
            "type": "object",
            "properties": {
                "read": {"$ref": "#/definitions/acl_defintion"},
            },
            "additionalProperties": False
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)
        return json_data


class ContainerConsumerValidator(ValidatorBase):
    """Validate a Consumer."""

    def __init__(self):
        self.name = 'Consumer'
        self.schema = {
            "type": "object",
            "properties": {
                "URL": {"type": "string", "maxLength": 255, "minLength": 1},
                "name": {"type": "string", "maxLength": 36, "minLength": 1}
            },
            "required": ["name", "URL"]
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)
        return json_data


class ContainerSecretValidator(ValidatorBase):
    """Validate a Container Secret."""

    def __init__(self):
        self.name = 'ContainerSecret'
        self.schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 255},
                "secret_ref": {"type": "string", "minLength": 1}
            },
            "required": ["secret_ref"]
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)
        return json_data


class ContainerValidator(ValidatorBase):
    """Validator for all types of Container."""

    def __init__(self):
        self.name = 'Container'
        self.schema = {
            "type": "object",
            "properties": {
                "name": {"type": ["string", "null"], "maxLength": 255},
                "type": {
                    "type": "string",
                    # TODO(hgedikli): move this to a common location
                    "enum": ["generic", "rsa", "certificate"]
                },
                "secret_refs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["secret_ref"],
                        "properties": {
                            "name": {
                                "type": ["string", "null"], "maxLength": 255
                            },
                            "secret_ref": {"type": "string", "minLength": 1}
                        }
                    }
                }
            },
            "required": ["type"]
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        container_type = json_data.get('type')
        secret_refs = json_data.get('secret_refs')

        if not secret_refs:
            return json_data

        secret_refs_names = set(secret_ref.get('name', '')
                                for secret_ref in secret_refs)

        self._assert_validity(
            len(secret_refs_names) == len(secret_refs),
            schema_name,
            u._("Duplicate reference names are not allowed"),
            "secret_refs")

        # The combination of container_id and secret_id is expected to be
        # primary key for container_secret so same secret id (ref) cannot be
        # used within a container
        secret_ids = set(self._get_secret_id_from_ref(secret_ref)
                         for secret_ref in secret_refs)

        self._assert_validity(
            len(secret_ids) == len(secret_refs),
            schema_name,
            u._("Duplicate secret ids are not allowed"),
            "secret_refs")

        # Ensure that our secret refs are valid relative to our config, no
        # spoofing allowed!
        req_host_href = utils.get_base_url_from_request()
        for secret_ref in secret_refs:
            if not secret_ref.get('secret_ref').startswith(req_host_href):
                raise exception.UnsupportedField(
                    field='secret_ref',
                    schema=schema_name,
                    reason=u._(
                        "Secret_ref does not match the configured hostname, "
                        "please try again"
                    )
                )

        if container_type == 'rsa':
            self._validate_rsa(secret_refs_names, schema_name)
        elif container_type == 'certificate':
            self._validate_certificate(secret_refs_names, schema_name)

        return json_data

    def _validate_rsa(self, secret_refs_names, schema_name):
        required_names = {'public_key', 'private_key'}
        optional_names = {'private_key_passphrase'}
        contains_unsupported_names = self._contains_unsupported_names(
            secret_refs_names, required_names | optional_names)
        self._assert_validity(
            not contains_unsupported_names,
            schema_name,
            u._("only 'private_key', 'public_key' and "
                "'private_key_passphrase' reference names are "
                "allowed for RSA type"),
            "secret_refs")

        self._assert_validity(
            self._has_minimum_required(secret_refs_names, required_names),
            schema_name,
            u._("The minimum required reference names are 'public_key' and"
                "'private_key' for RSA type"),
            "secret_refs")

    def _validate_certificate(self, secret_refs_names, schema_name):
        required_names = {'certificate'}
        optional_names = {'private_key', 'private_key_passphrase',
                          'intermediates'}
        contains_unsupported_names = self._contains_unsupported_names(
            secret_refs_names, required_names.union(optional_names))
        self._assert_validity(
            not contains_unsupported_names,
            schema_name,
            u._("only 'private_key', 'certificate' , "
                "'private_key_passphrase',  or 'intermediates' "
                "reference names are allowed for Certificate type"),
            "secret_refs")

        self._assert_validity(
            self._has_minimum_required(secret_refs_names, required_names),
            schema_name,
            u._("The minimum required reference name is 'certificate' "
                "for Certificate type"),
            "secret_refs")

    def _contains_unsupported_names(self, secret_refs_names, supported_names):
        if secret_refs_names.difference(supported_names):
            return True
        return False

    def _has_minimum_required(self, secret_refs_names, required_names):
        if required_names.issubset(secret_refs_names):
            return True
        return False

    def _get_secret_id_from_ref(self, secret_ref):
        secret_id = secret_ref.get('secret_ref')
        if secret_id.endswith('/'):
            secret_id = secret_id.rsplit('/', 2)[1]
        elif '/' in secret_id:
            secret_id = secret_id.rsplit('/', 1)[1]

        return secret_id


class NewTransportKeyValidator(ValidatorBase):
    """Validate a new transport key."""

    def __init__(self):
        self.name = 'Transport Key'

        self.schema = {
            "type": "object",
            "properties": {
                "plugin_name": {"type": "string"},
                "transport_key": {"type": "string"},
            },
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        plugin_name = json_data.get('plugin_name', '').strip()
        self._assert_validity(plugin_name,
                              schema_name,
                              u._("plugin_name must be provided"),
                              "plugin_name")
        json_data['plugin_name'] = plugin_name

        transport_key = json_data.get('transport_key', '').strip()
        self._assert_validity(transport_key,
                              schema_name,
                              u._("transport_key must be provided"),
                              "transport_key")
        json_data['transport_key'] = transport_key

        return json_data


class ProjectQuotaValidator(ValidatorBase):
    """Validate a new project quota."""

    def __init__(self):
        self.name = 'Project Quota'

        self.schema = {
            'type': 'object',
            'properties': {
                'project_quotas': {
                    'type': 'object',
                    'properties': {
                        'secrets': {'type': 'integer'},
                        'orders': {'type': 'integer'},
                        'containers': {'type': 'integer'},
                        'consumers': {'type': 'integer'},
                        'cas': {'type': 'integer'}
                    },
                    'additionalProperties': False,
                }
            },
            'required': ['project_quotas'],
            'additionalProperties': False
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        return json_data


class NewCAValidator(ValidatorBase, CACommonHelpersMixin):
    """Validate new CA(s)."""

    def __init__(self):
        self.name = 'CA'

        self.schema = {
            'type': 'object',
            'properties': {
                'name': {'type': 'string', "minLength": 1},
                'subject_dn': {'type': 'string', "minLength": 1},
                'parent_ca_ref': {'type': 'string', "minLength": 1},
                'description': {'type': 'string'},
            },
            'required': ['name', 'subject_dn', 'parent_ca_ref'],
            'additionalProperties': False
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        subject_dn = json_data['subject_dn']
        self._validate_subject_dn_data(subject_dn)
        return json_data


class SecretConsumerValidator(ValidatorBase):
    """Validate a new Secret Consumer."""

    def __init__(self):
        self.name = "Secret Consumer"

        self.schema = {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "maxLength": 255,
                    "minLength": 1,
                },
                "resource_type": {
                    "type": "string",
                    "maxLength": 255,
                    "minLength": 1,
                },
                "resource_id": {"type": "string", "minLength": 1},
            },
            "required": ["service", "resource_type", "resource_id"],
        }

    def validate(self, json_data, parent_schema=None):
        schema_name = self._full_name(parent_schema)

        self._assert_schema_is_valid(json_data, schema_name)

        return json_data
