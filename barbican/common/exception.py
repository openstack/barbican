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


import urlparse
from barbican.openstack.common.gettextutils import _

_FATAL_EXCEPTION_FORMAT_ERRORS = False


class RedirectException(Exception):
    def __init__(self, url):
        self.url = urlparse.urlparse(url)


class BarbicanException(Exception):
    """
    Base Barbican Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred")

    def __init__(self, message=None, *args, **kwargs):
        if not message:
            message = self.message
        try:
            message = message % kwargs
        except Exception as e:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise e
            else:
                # at least get the core message out if something happened
                pass
        super(BarbicanException, self).__init__(message)


class MissingArgumentError(BarbicanException):
    message = _("Missing required argument.")


class MissingCredentialError(BarbicanException):
    message = _("Missing required credential: %(required)s")


class BadAuthStrategy(BarbicanException):
    message = _("Incorrect auth strategy, expected \"%(expected)s\" but "
                "received \"%(received)s\"")


class NotFound(BarbicanException):
    message = _("An object with the specified identifier was not found.")


class UnknownScheme(BarbicanException):
    message = _("Unknown scheme '%(scheme)s' found in URI")


class BadStoreUri(BarbicanException):
    message = _("The Store URI was malformed.")


class Duplicate(BarbicanException):
    message = _("An object with the same identifier already exists.")


class StorageFull(BarbicanException):
    message = _("There is not enough disk space on the image storage media.")


class StorageWriteDenied(BarbicanException):
    message = _("Permission to write image storage media denied.")


class AuthBadRequest(BarbicanException):
    message = _("Connect error/bad request to Auth service at URL %(url)s.")


class AuthUrlNotFound(BarbicanException):
    message = _("Auth service at URL %(url)s not found.")


class AuthorizationFailure(BarbicanException):
    message = _("Authorization failed.")


class NotAuthenticated(BarbicanException):
    message = _("You are not authenticated.")


class Forbidden(BarbicanException):
    message = _("You are not authorized to complete this action.")


class NotSupported(BarbicanException):
    message = _("Operation is not supported.")


class ForbiddenPublicImage(Forbidden):
    message = _("You are not authorized to complete this action.")


class ProtectedImageDelete(Forbidden):
    message = _("Image %(image_id)s is protected and cannot be deleted.")


#NOTE(bcwaldon): here for backwards-compatability, need to deprecate.
class NotAuthorized(Forbidden):
    message = _("You are not authorized to complete this action.")


class Invalid(BarbicanException):
    message = _("Data supplied was not valid.")


class NoDataToProcess(BarbicanException):
    message = _("No data supplied to process.")


class InvalidSortKey(Invalid):
    message = _("Sort key supplied was not valid.")


class InvalidFilterRangeValue(Invalid):
    message = _("Unable to filter using the specified range.")


class ReadonlyProperty(Forbidden):
    message = _("Attribute '%(property)s' is read-only.")


class ReservedProperty(Forbidden):
    message = _("Attribute '%(property)s' is reserved.")


class AuthorizationRedirect(BarbicanException):
    message = _("Redirecting to %(uri)s for authorization.")


class DatabaseMigrationError(BarbicanException):
    message = _("There was an error migrating the database.")


class ClientConnectionError(BarbicanException):
    message = _("There was an error connecting to a server")


class ClientConfigurationError(BarbicanException):
    message = _("There was an error configuring the client.")


class MultipleChoices(BarbicanException):
    message = _("The request returned a 302 Multiple Choices. This generally "
                "means that you have not included a version indicator in a "
                "request URI.\n\nThe body of response returned:\n%(body)s")


class LimitExceeded(BarbicanException):
    message = _("The request returned a 413 Request Entity Too Large. This "
                "generally means that rate limiting or a quota threshold was "
                "breached.\n\nThe response body:\n%(body)s")

    def __init__(self, *args, **kwargs):
        super(LimitExceeded, self).__init__(*args, **kwargs)
        self.retry_after = (int(kwargs['retry']) if kwargs.get('retry')
                            else None)


class ServiceUnavailable(BarbicanException):
    message = _("The request returned 503 Service Unavilable. This "
                "generally occurs on service overload or other transient "
                "outage.")

    def __init__(self, *args, **kwargs):
        super(ServiceUnavailable, self).__init__(*args, **kwargs)
        self.retry_after = (int(kwargs['retry']) if kwargs.get('retry')
                            else None)


class ServerError(BarbicanException):
    message = _("The request returned 500 Internal Server Error.")


class UnexpectedStatus(BarbicanException):
    message = _("The request returned an unexpected status: %(status)s."
                "\n\nThe response body:\n%(body)s")


class InvalidContentType(BarbicanException):
    message = _("Invalid content type %(content_type)s")


class InvalidContentEncoding(BarbicanException):
    message = _("Invalid content encoding %(content_encoding)s")


class PayloadDecodingError(BarbicanException):
    message = _("Error while attempting to decode payload.")


class BadRegistryConnectionConfiguration(BarbicanException):
    message = _("Registry was not configured correctly on API server. "
                "Reason: %(reason)s")


class BadStoreConfiguration(BarbicanException):
    message = _("Store %(store_name)s could not be configured correctly. "
                "Reason: %(reason)s")


class BadDriverConfiguration(BarbicanException):
    message = _("Driver %(driver_name)s could not be configured correctly. "
                "Reason: %(reason)s")


class StoreDeleteNotSupported(BarbicanException):
    message = _("Deleting images from this store is not supported.")


class StoreAddDisabled(BarbicanException):
    message = _("Configuration for store failed. Adding images to this "
                "store is disabled.")


class InvalidNotifierStrategy(BarbicanException):
    message = _("'%(strategy)s' is not an available notifier strategy.")


class MaxRedirectsExceeded(BarbicanException):
    message = _("Maximum redirects (%(redirects)s) was exceeded.")


class InvalidRedirect(BarbicanException):
    message = _("Received invalid HTTP redirect.")


class NoServiceEndpoint(BarbicanException):
    message = _("Response from Keystone does not contain a Barbican endpoint.")


class RegionAmbiguity(BarbicanException):
    message = _("Multiple 'image' service matches for region %(region)s. This "
                "generally means that a region is required and you have not "
                "supplied one.")


class WorkerCreationFailure(BarbicanException):
    message = _("Server worker creation failed: %(reason)s.")


class SchemaLoadError(BarbicanException):
    message = _("Unable to load schema: %(reason)s")


class InvalidObject(BarbicanException):
    message = _("Provided object does not match schema "
                "'%(schema)s': %(reason)s")

    def __init__(self, *args, **kwargs):
        super(InvalidObject, self).__init__(*args, **kwargs)
        self.invalid_property = kwargs.get('property')


class UnsupportedField(BarbicanException):
    message = _("No support for value set on field '%(field)s' on "
                "schema '%(schema)s': %(reason)s")

    def __init__(self, *args, **kwargs):
        super(UnsupportedField, self).__init__(*args, **kwargs)
        self.invalid_field = kwargs.get('field')


class UnsupportedHeaderFeature(BarbicanException):
    message = _("Provided header feature is unsupported: %(feature)s")


class InUseByStore(BarbicanException):
    message = _("The image cannot be deleted because it is in use through "
                "the backend store outside of Barbican.")


class ImageSizeLimitExceeded(BarbicanException):
    message = _("The provided image is too large.")
