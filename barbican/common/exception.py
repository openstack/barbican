# Copyright (c) 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Barbican exception subclasses
"""

from barbican import i18n as u

_FATAL_EXCEPTION_FORMAT_ERRORS = False


class BarbicanException(Exception):
    """Base Barbican Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = u._("An unknown exception occurred")

    def __init__(self, message_arg=None, *args, **kwargs):
        if not message_arg:
            message_arg = self.message
        try:
            self.message = message_arg % kwargs
        except Exception as e:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise e
            else:
                # at least get the core message out if something happened
                pass
        super(BarbicanException, self).__init__(self.message)


class BarbicanHTTPException(BarbicanException):
    """Base Barbican Exception to handle HTTP responses

    To correctly use this class, inherit from it and define the following
    properties:

    - message: The message that will be displayed in the server log.
    - client_message: The message that will actually be outputted to the
                      client.
    - status_code: The HTTP status code that should be returned.
                   The default status code is 500.
    """
    client_message = u._("failure seen - please contact site administrator.")
    status_code = 500

    def __init__(self, message_arg=None, client_message=None, *args, **kwargs):
        if not client_message:
            client_message = self.client_message
        try:
            self.client_message = client_message % kwargs
        except Exception as e:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise e
            else:
                # at least get the core message out if something happened
                pass
        super(BarbicanHTTPException, self).__init__(
            message_arg, self.client_message, *args, **kwargs)


class MissingArgumentError(BarbicanException):
    message = u._("Missing required argument.")


class MissingMetadataField(BarbicanHTTPException):
    message = u._("Missing required metadata field for %(required)s")
    client_message = message
    status_code = 400


class InvalidMetadataRequest(BarbicanHTTPException):
    message = u._("Invalid Metadata. Keys and Values must be Strings.")
    client_message = message
    status_code = 400


class InvalidMetadataKey(BarbicanHTTPException):
    message = u._("Invalid Key. Key must be URL safe.")
    client_message = message
    status_code = 400


class InvalidSubjectDN(BarbicanHTTPException):
    message = u._("Invalid subject DN: %(subject_dn)s")
    client_message = message
    status_code = 400


class InvalidContainer(BarbicanHTTPException):
    message = u._("Invalid container: %(reason)s")
    client_message = message
    status_code = 400


class InvalidExtensionsData(BarbicanHTTPException):
    message = u._("Invalid extensions data.")
    client_message = message
    status_code = 400


class InvalidCMCData(BarbicanHTTPException):
    message = u._("Invalid CMC Data")
    client_message = message
    status_code = 400


class InvalidPKCS10Data(BarbicanHTTPException):
    message = u._("Invalid PKCS10 Data: %(reason)s")
    client_message = message
    status_code = 400


class InvalidCertificateRequestType(BarbicanHTTPException):
    message = u._("Invalid Certificate Request Type")
    client_message = message
    status_code = 400


class CertificateExtensionsNotSupported(BarbicanHTTPException):
    message = u._("Extensions are not yet supported.  "
                  "Specify a valid profile instead.")
    client_message = message
    status_code = 400


class FullCMCNotSupported(BarbicanHTTPException):
    message = u._("Full CMC Requests are not yet supported.")
    client_message = message
    status_code = 400


class NotFound(BarbicanException):
    message = u._("An object with the specified identifier was not found.")


class ConstraintCheck(BarbicanException):
    message = u._("A defined SQL constraint check failed: %(error)s")


class NotSupported(BarbicanException):
    message = u._("Operation is not supported.")


class Invalid(BarbicanException):
    message = u._("Data supplied was not valid.")


class NoDataToProcess(BarbicanHTTPException):
    message = u._("No data supplied to process.")
    client_message = message
    status_code = 400


class LimitExceeded(BarbicanHTTPException):
    message = u._("The request returned a 413 Request Entity Too Large. This "
                  "generally means that rate limiting or a quota threshold "
                  "was breached.")
    client_message = u._("Provided information too large to process")
    status_code = 413

    def __init__(self, *args, **kwargs):
        super(LimitExceeded, self).__init__(*args, **kwargs)
        self.retry_after = (int(kwargs['retry']) if kwargs.get('retry')
                            else None)


class InvalidObject(BarbicanHTTPException):
    status_code = 400

    def __init__(self, *args, **kwargs):
        self.invalid_property = kwargs.get('property')
        self.message = u._("Failed to validate JSON information: ")
        self.client_message = u._("Provided object does not match "
                                  "schema '{schema}': "
                                  "{reason}. Invalid property: "
                                  "'{property}'").format(*args, **kwargs)
        self.message = self.message + self.client_message
        super(InvalidObject, self).__init__(*args, **kwargs)


class PayloadDecodingError(BarbicanHTTPException):
    status_code = 400
    message = u._("Error while attempting to decode payload.")
    client_message = u._("Unable to decode request data.")


class UnsupportedField(BarbicanHTTPException):
    message = u._("No support for value set on field '%(field)s' on "
                  "schema '%(schema)s': %(reason)s")
    client_message = u._("Provided field value is not supported")
    status_code = 400

    def __init__(self, *args, **kwargs):
        super(UnsupportedField, self).__init__(*args, **kwargs)
        self.invalid_field = kwargs.get('field')


class FeatureNotImplemented(BarbicanException):
    message = u._("Feature not implemented for value set on field "
                  "'%(field)s' on " "schema '%(schema)s': %(reason)s")

    def __init__(self, *args, **kwargs):
        super(FeatureNotImplemented, self).__init__(*args, **kwargs)
        self.invalid_field = kwargs.get('field')


class StoredKeyContainerNotFound(BarbicanException):
    message = u._("Container %(container_id)s does not exist for stored "
                  "key certificate generation.")


class StoredKeyPrivateKeyNotFound(BarbicanException):
    message = u._("Container %(container_id)s does not reference a private "
                  "key needed for stored key certificate generation.")


class ProvidedTransportKeyNotFound(BarbicanHTTPException):
    message = u._("Provided Transport key %(transport_key_id)s "
                  "could not be found")
    client_message = u._("Provided transport key was not found.")
    status_code = 400


class InvalidCAID(BarbicanHTTPException):
    message = u._("Invalid CA_ID: %(ca_id)s")
    client_message = u._("The ca_id provided in the request is invalid")
    status_code = 400


class CANotDefinedForProject(BarbicanHTTPException):
    message = u._("CA specified by ca_id %(ca_id)s not defined for project: "
                  "%(project_id)s")
    client_message = u._("The ca_id provided in the request is not defined "
                         "for this project")
    status_code = 403


class QuotaReached(BarbicanHTTPException):
    message = u._("Quota reached for project %(external_project_id)s. Only "
                  "%(quota)s %(resource_type)s are allowed.")
    client_message = u._("Creation not allowed because a quota has "
                         "been reached")
    status_code = 403

    def __init__(self, *args, **kwargs):
        super(QuotaReached, self).__init__(*args, **kwargs)
        self.external_project_id = kwargs.get('external_project_id')
        self.quota = kwargs.get('quota')
        self.resource_type = kwargs.get('resource_type')


class InvalidParentCA(BarbicanHTTPException):
    message = u._("Invalid Parent CA: %(parent_ca_ref)s")
    client_message = message
    status_code = 400


class SubCAsNotSupported(BarbicanHTTPException):
    message = u._("Plugin does not support generation of subordinate CAs")
    client_message = message
    status_code = 400


class SubCANotCreated(BarbicanHTTPException):
    message = u._("Errors in creating subordinate CA: %(name)")
    client_message = message


class CannotDeleteBaseCA(BarbicanHTTPException):
    message = u._("Only subordinate CAs can be deleted.")
    status_code = 403


class UnauthorizedSubCA(BarbicanHTTPException):
    message = u._("Subordinate CA is not owned by this project")
    client_message = message
    status_code = 403


class CannotDeletePreferredCA(BarbicanHTTPException):
    message = u._("A new project preferred CA must be set "
                  "before this one can be deleted.")
    status_code = 409


class BadSubCACreationRequest(BarbicanHTTPException):
    message = u._("Errors returned by CA when attempting to "
                  "create subordinate CA: %(reason)s")
    client_message = message
    status_code = 400


class SubCACreationErrors(BarbicanHTTPException):
    message = u._("Errors returned by CA when attempting to create "
                  "subordinate CA: %(reason)s")
    client_message = message


class SubCADeletionErrors(BarbicanHTTPException):
    message = u._("Errors returned by CA when attempting to delete "
                  "subordinate CA: %(reason)s")
    client_message = message


class PKCS11Exception(BarbicanException):
    message = u._("There was an error with the PKCS#11 library.")


class P11CryptoPluginKeyException(PKCS11Exception):
    message = u._("More than one key found for label")


class P11CryptoPluginException(PKCS11Exception):
    message = u._("General exception")


class P11CryptoKeyHandleException(PKCS11Exception):
    message = u._("No key handle was found")


class P11CryptoTokenException(PKCS11Exception):
    message = u._("No token was found in slot %(slot_id)s")


class TrustwayProteccioException(PKCS11Exception):
    message = u._("Trustway Proteccio HSM Error")


class MultipleStorePreferredPluginMissing(BarbicanException):
    """Raised when a preferred plugin is missing in service configuration."""
    def __init__(self, store_name):
        super(MultipleStorePreferredPluginMissing, self).__init__(
            u._("Preferred Secret Store plugin '{store_name}' is not "
                "currently set in service configuration. This is probably a "
                "server misconfiguration.").format(
                store_name=store_name)
        )
        self.store_name = store_name


class MultipleStorePluginStillInUse(BarbicanException):
    """Raised when a used plugin is missing in service configuration."""
    def __init__(self, store_name):
        super(MultipleStorePluginStillInUse, self).__init__(
            u._("Secret Store plugin '{store_name}' is still in use and can "
                "not be removed. Its missing in service configuration. This is"
                " probably a server misconfiguration.").format(
                store_name=store_name)
        )
        self.store_name = store_name


class MultipleSecretStoreLookupFailed(BarbicanException):
    """Raised when a plugin lookup suffix is missing during config read."""
    def __init__(self):
        msg = u._("Plugin lookup property 'stores_lookup_suffix' is not "
                  "defined in service configuration")
        super(MultipleSecretStoreLookupFailed, self).__init__(msg)


class MultipleStoreIncorrectGlobalDefault(BarbicanException):
    """Raised when a global default for only one plugin is not set to True."""
    def __init__(self, occurrence):
        msg = None
        if occurrence > 1:
            msg = u._("There are {count} plugins with global default as "
                      "True in service configuration. Only one plugin can have"
                      " this as True").format(count=occurrence)
        else:
            msg = u._("There is no plugin defined with global default as True."
                      " One of plugin must be identified as global default")

        super(MultipleStoreIncorrectGlobalDefault, self).__init__(msg)


class MultipleStorePluginValueMissing(BarbicanException):
    """Raised when a store plugin value is missing in service configuration."""
    def __init__(self, section_name):
        super(MultipleStorePluginValueMissing, self).__init__(
            u._("In section '{0}', secret_store_plugin value is missing"
                ).format(section_name)
        )
        self.section_name = section_name
