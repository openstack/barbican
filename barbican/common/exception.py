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


class MissingCredentialError(BarbicanException):
    message = u._("Missing required credential: %(required)s")


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


class BadAuthStrategy(BarbicanException):
    message = u._("Incorrect auth strategy, expected \"%(expected)s\" but "
                  "received \"%(received)s\"")


class NotFound(BarbicanException):
    message = u._("An object with the specified identifier was not found.")


class UnknownScheme(BarbicanException):
    message = u._("Unknown scheme '%(scheme)s' found in URI")


class BadStoreUri(BarbicanException):
    message = u._("The Store URI was malformed.")


class Duplicate(BarbicanException):
    message = u._("An object with the same identifier already exists.")


class StorageFull(BarbicanException):
    message = u._("There is not enough disk space on the image storage media.")


class StorageWriteDenied(BarbicanException):
    message = u._("Permission to write image storage media denied.")


class AuthBadRequest(BarbicanException):
    message = u._("Connect error/bad request to Auth service at URL %(url)s.")


class AuthUrlNotFound(BarbicanException):
    message = u._("Auth service at URL %(url)s not found.")


class AuthorizationFailure(BarbicanException):
    message = u._("Authorization failed.")


class NotAuthenticated(BarbicanException):
    message = u._("You are not authenticated.")


class Forbidden(BarbicanException):
    message = u._("You are not authorized to complete this action.")


class NotSupported(BarbicanException):
    message = u._("Operation is not supported.")


class ForbiddenPublicImage(Forbidden):
    message = u._("You are not authorized to complete this action.")


class ProtectedImageDelete(Forbidden):
    message = u._("Image %(image_id)s is protected and cannot be deleted.")


# NOTE(bcwaldon): here for backwards-compatibility, need to deprecate.
class NotAuthorized(Forbidden):
    message = u._("You are not authorized to complete this action.")


class Invalid(BarbicanException):
    message = u._("Data supplied was not valid.")


class NoDataToProcess(BarbicanHTTPException):
    message = u._("No data supplied to process.")
    client_message = message
    status_code = 400


class InvalidSortKey(Invalid):
    message = u._("Sort key supplied was not valid.")


class InvalidFilterRangeValue(Invalid):
    message = u._("Unable to filter using the specified range.")


class ReadonlyProperty(Forbidden):
    message = u._("Attribute '%(property)s' is read-only.")


class ReservedProperty(Forbidden):
    message = u._("Attribute '%(property)s' is reserved.")


class AuthorizationRedirect(BarbicanException):
    message = u._("Redirecting to %(uri)s for authorization.")


class DatabaseMigrationError(BarbicanException):
    message = u._("There was an error migrating the database.")


class ClientConnectionError(BarbicanException):
    message = u._("There was an error connecting to a server")


class ClientConfigurationError(BarbicanException):
    message = u._("There was an error configuring the client.")


class MultipleChoices(BarbicanException):
    message = u._("The request returned a 302 Multiple Choices. This "
                  "generally means that you have not included a version "
                  "indicator in a request URI.\n\nThe body of response "
                  "returned:\n%(body)s")


class LimitExceeded(BarbicanHTTPException):
    message = u._("The request returned a 413 Request Entity Too Large. This "
                  "generally means that rate limiting or a quota threshold "
                  "was breached.\n\nThe response body:\n%(body)s")
    client_message = u._("Provided information too large to process")
    status_code = 413

    def __init__(self, *args, **kwargs):
        super(LimitExceeded, self).__init__(*args, **kwargs)
        self.retry_after = (int(kwargs['retry']) if kwargs.get('retry')
                            else None)


class ServiceUnavailable(BarbicanException):
    message = u._("The request returned 503 Service Unavilable. This "
                  "generally occurs on service overload or other transient "
                  "outage.")

    def __init__(self, *args, **kwargs):
        super(ServiceUnavailable, self).__init__(*args, **kwargs)
        self.retry_after = (int(kwargs['retry']) if kwargs.get('retry')
                            else None)


class ServerError(BarbicanException):
    message = u._("The request returned 500 Internal Server Error.")


class UnexpectedStatus(BarbicanException):
    message = u._("The request returned an unexpected status: %(status)s."
                  "\n\nThe response body:\n%(body)s")


class InvalidContentType(BarbicanException):
    message = u._("Invalid content type %(content_type)s")


class InvalidContentEncoding(BarbicanException):
    message = u._("Invalid content encoding %(content_encoding)s")


class BadRegistryConnectionConfiguration(BarbicanException):
    message = u._("Registry was not configured correctly on API server. "
                  "Reason: %(reason)s")


class BadStoreConfiguration(BarbicanException):
    message = u._("Store %(store_name)s could not be configured correctly. "
                  "Reason: %(reason)s")


class BadDriverConfiguration(BarbicanException):
    message = u._("Driver %(driver_name)s could not be configured correctly. "
                  "Reason: %(reason)s")


class StoreDeleteNotSupported(BarbicanException):
    message = u._("Deleting images from this store is not supported.")


class StoreAddDisabled(BarbicanException):
    message = u._("Configuration for store failed. Adding images to this "
                  "store is disabled.")


class InvalidNotifierStrategy(BarbicanException):
    message = u._("'%(strategy)s' is not an available notifier strategy.")


class MaxRedirectsExceeded(BarbicanException):
    message = u._("Maximum redirects (%(redirects)s) was exceeded.")


class InvalidRedirect(BarbicanException):
    message = u._("Received invalid HTTP redirect.")


class NoServiceEndpoint(BarbicanException):
    message = u._("Response from Keystone does not contain a "
                  "Barbican endpoint.")


class RegionAmbiguity(BarbicanException):
    message = u._("Multiple 'image' service matches for region %(region)s. "
                  "This generally means that a region is required and you "
                  "have not supplied one.")


class WorkerCreationFailure(BarbicanException):
    message = u._("Server worker creation failed: %(reason)s.")


class SchemaLoadError(BarbicanException):
    message = u._("Unable to load schema: %(reason)s")


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


class UnsupportedHeaderFeature(BarbicanException):
    message = u._("Provided header feature is unsupported: %(feature)s")


class InUseByStore(BarbicanException):
    message = u._("The image cannot be deleted because it is in use through "
                  "the backend store outside of Barbican.")


class ImageSizeLimitExceeded(BarbicanException):
    message = u._("The provided image is too large.")


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
                  "create subordinate CA: %(reason)")
    client_message = message
    status_code = 400


class SubCACreationErrors(BarbicanHTTPException):
    message = u._("Errors returned by CA when attempting to create "
                  "subordinate CA: %(reason)")
    client_message = message


class SubCADeletionErrors(BarbicanHTTPException):
    message = u._("Errors returned by CA when attempting to delete "
                  "subordinate CA: %(reason)")
    client_message = message
