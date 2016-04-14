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
SSL Certificate resources for Barbican.

The resources here should be generic across all certificate-related
implementations. Hence do not place vendor-specific content in this module.
"""

import abc
import datetime

from oslo_config import cfg
import six
from stevedore import named

from barbican.common import config
from barbican.common import exception
import barbican.common.utils as utils
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin.util import utils as plugin_utils

LOG = utils.getLogger(__name__)
CONF = config.new_config()

# Configuration for certificate processing plugins:
DEFAULT_PLUGIN_NAMESPACE = 'barbican.certificate.plugin'
DEFAULT_PLUGINS = ['simple_certificate']

cert_opt_group = cfg.OptGroup(name='certificate',
                              title='Certificate Plugin Options')
cert_opts = [
    cfg.StrOpt('namespace',
               default=DEFAULT_PLUGIN_NAMESPACE,
               help=u._('Extension namespace to search for plugins.')
               ),
    cfg.MultiStrOpt('enabled_certificate_plugins',
                    default=DEFAULT_PLUGINS,
                    help=u._('List of certificate plugins to load.')
                    )
]
CONF.register_group(cert_opt_group)
CONF.register_opts(cert_opts, group=cert_opt_group)
config.parse_args(CONF)


# Configuration for certificate eventing plugins:
DEFAULT_EVENT_PLUGIN_NAMESPACE = 'barbican.certificate.event.plugin'
DEFAULT_EVENT_PLUGINS = ['simple_certificate_event']

cert_event_opt_group = cfg.OptGroup(name='certificate_event',
                                    title='Certificate Event Plugin Options')
cert_event_opts = [
    cfg.StrOpt('namespace',
               default=DEFAULT_EVENT_PLUGIN_NAMESPACE,
               help=u._('Extension namespace to search for eventing plugins.')
               ),
    cfg.MultiStrOpt('enabled_certificate_event_plugins',
                    default=DEFAULT_EVENT_PLUGINS,
                    help=u._('List of certificate plugins to load.')
                    )
]
CONF.register_group(cert_event_opt_group)
CONF.register_opts(cert_event_opts, group=cert_event_opt_group)


ERROR_RETRY_MSEC = 300000
RETRY_MSEC = 3600000
CA_INFO_DEFAULT_EXPIRATION_DAYS = 1

CA_PLUGIN_TYPE_DOGTAG = "dogtag"
CA_PLUGIN_TYPE_SYMANTEC = "symantec"

# fields to distinguish CA types and subject key identifiers
CA_TYPE = "ca_type"
CA_SUBJECT_KEY_IDENTIFIER = "ca_subject_key_identifier"

# field to get the certificate request type
REQUEST_TYPE = "request_type"

# fields for the ca_id, plugin_ca_id
CA_ID = "ca_id"
PLUGIN_CA_ID = "plugin_ca_id"

# fields for ca_info dict keys
INFO_NAME = "name"
INFO_DESCRIPTION = "description"
INFO_CA_SIGNING_CERT = "ca_signing_certificate"
INFO_INTERMEDIATES = "intermediates"
INFO_EXPIRATION = "expiration"


# Singleton to avoid loading the CertificateEventManager plugins more than once
_EVENT_PLUGIN_MANAGER = None


class CertificateRequestType(object):
    """Constants to define the certificate request type."""
    CUSTOM_REQUEST = "custom"
    FULL_CMC_REQUEST = "full-cmc"
    SIMPLE_CMC_REQUEST = "simple-cmc"
    STORED_KEY_REQUEST = "stored-key"


class CertificatePluginNotFound(exception.BarbicanException):
    """Raised when no certificate plugin supporting a request is available."""
    def __init__(self, plugin_name=None):
        if plugin_name:
            message = u._(
                'Certificate plugin "{name}"'
                ' not found.').format(name=plugin_name)
        else:
            message = u._("Certificate plugin not found or configured.")
        super(CertificatePluginNotFound, self).__init__(message)


class CertificatePluginNotFoundForCAID(exception.BarbicanException):
    """Raised when no certificate plugin is available for a CA_ID."""
    def __init__(self, ca_id):
        message = u._(
            'Certificate plugin not found for "{ca_id}".').format(ca_id=ca_id)
        super(CertificatePluginNotFoundForCAID, self).__init__(message)


class CertificateEventPluginNotFound(exception.BarbicanException):
    """Raised with no certificate event plugin supporting request."""
    def __init__(self, plugin_name=None):
        if plugin_name:
            message = u._(
                'Certificate event plugin "{name}" '
                'not found.').format(name=plugin_name)
        else:
            message = u._("Certificate event plugin not found.")
        super(CertificateEventPluginNotFound, self).__init__(message)


class CertificateStatusNotSupported(exception.BarbicanException):
    """Raised when cert status returned is unknown."""
    def __init__(self, status):
        super(CertificateStatusNotSupported, self).__init__(
            u._("Certificate status of {status} not "
                "supported").format(status=status)
        )
        self.status = status


class CertificateGeneralException(exception.BarbicanException):
    """Raised when a system fault has occurred."""
    def __init__(self, reason=u._('Unknown')):
        super(CertificateGeneralException, self).__init__(
            u._('Problem seen during certificate processing - '
                'Reason: {reason}').format(reason=reason)
        )
        self.reason = reason


class CertificateStatusClientDataIssue(exception.BarbicanHTTPException):
    """Raised when the CA has encountered an issue with request data."""

    client_message = ""
    status_code = 400

    def __init__(self, reason=u._('Unknown')):
        super(CertificateStatusClientDataIssue, self).__init__(
            u._('Problem with data in certificate request - '
                'Reason: {reason}').format(reason=reason)
        )
        self.client_message = self.message


class CertificateStatusInvalidOperation(exception.BarbicanHTTPException):
    """Raised when the CA has encountered an issue with request data."""

    client_message = ""
    status_code = 400

    def __init__(self, reason=u._('Unknown')):
        super(CertificateStatusInvalidOperation, self).__init__(
            u._('Invalid operation requested - '
                'Reason: {reason}').format(reason=reason)
        )
        self.client_message = self.message


@six.add_metaclass(abc.ABCMeta)
class CertificateEventPluginBase(object):
    """Base class for certificate eventing plugins.

    This class is the base plugin contract for issuing certificate related
    events from Barbican.
    """

    @abc.abstractmethod
    def notify_certificate_is_ready(
            self, project_id, order_ref, container_ref):
        """Notify that a certificate has been generated and is ready to use.

        :param project_id: Project ID associated with this certificate
        :param order_ref: HATEOAS reference URI to the submitted Barbican Order
        :param container_ref: HATEOAS reference URI to the Container storing
               the certificate
        :returns: None
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def notify_ca_is_unavailable(
            self, project_id, order_ref, error_msg, retry_in_msec):
        """Notify that the certificate authority (CA) isn't available.

        :param project_id: Project ID associated with this order
        :param order_ref: HATEOAS reference URI to the submitted Barbican Order
        :param error_msg: Error message if it is available
        :param retry_in_msec: Delay before attempting to talk to the CA again.
               If this is 0, then no attempt will be made.
        :returns: None
        """
        raise NotImplementedError  # pragma: no cover


@six.add_metaclass(abc.ABCMeta)
class CertificatePluginBase(object):
    """Base class for certificate plugins.

    This class is the base plugin contract for certificates.
    """

    @abc.abstractmethod
    def get_default_ca_name(self):
        """Get the default CA name

        Provides a default CA name to be returned in the default
        get_ca_info() method.  If get_ca_info() is overridden (to
        support multiple CAs for instance), then this method may not
        be called.  In that case, just implement this method to return
        a dummy variable.

        If this value is used, it should be unique amongst all the CA
        plugins.

        :return: The default CA name
        :rtype: str
        """
        raise NotImplementedError   # pragma: no cover

    @abc.abstractmethod
    def get_default_signing_cert(self):
        """Get the default CA signing cert

        Provides a default CA signing cert to be returned in the default
        get_ca_info() method.  If get_ca_info() is overridden (to
        support multiple CAs for instance), then this method may not
        be called.  In that case, just implement this method to return
        a dummy variable.
        :return: The default CA signing cert
        :rtype: str
        """
        raise NotImplementedError   # pragma: no cover

    @abc.abstractmethod
    def get_default_intermediates(self):
        """Get the default CA certificate chain

        Provides a default CA certificate to be returned in the default
        get_ca_info() method.  If get_ca_info() is overridden (to
        support multiple CAs for instance), then this method may not
        be called.  In that case, just implement this method to return
        a dummy variable.
        :return: The default CA certificate chain
        :rtype: str
        """
        raise NotImplementedError   # pragma: no cover

    @abc.abstractmethod
    def issue_certificate_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Create the initial order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :param barbican_meta_dto:
            Data transfer object :class:`BarbicanMetaDTO` containing data
            added to the request by the Barbican server to provide additional
            context for processing, but which are not in
            the original request.  For example, the plugin_ca_id
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def modify_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :param barbican_meta_dto:
            Data transfer object :class:`BarbicanMetaDTO` containing data
            added to the request by the Barbican server to provide additional
            context for processing, but which are not in
            the original request.  For example, the plugin_ca_id
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :param barbican_meta_dto:
            Data transfer object :class:`BarbicanMetaDTO` containing data
            added to the request by the Barbican server to provide additional
            context for processing, but which are not in
            the original request.  For example, the plugin_ca_id
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def check_certificate_status(self, order_id, order_meta, plugin_meta,
                                 barbican_meta_dto):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :param barbican_meta_dto:
            Data transfer object :class:`BarbicanMetaDTO` containing data
            added to the request by the Barbican server to provide additional
            context for processing, but which are not in
            the original request.  For example, the plugin_ca_id
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def supports(self, certificate_spec):
        """Returns if the plugin supports the certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        raise NotImplementedError  # pragma: no cover

    def supported_request_types(self):
        """Returns the request_types supported by this plugin.

        :returns: a list of the Barbican-core defined request_types
                  supported by this plugin.
        """
        return [CertificateRequestType.CUSTOM_REQUEST]  # pragma: no cover

    def get_ca_info(self):
        """Returns information about the CA(s) supported by this plugin.

        :returns: dictionary indexed by plugin_ca_id.  Each entry consists
                  of a dictionary of key-value pairs.

        An example dictionary containing the current supported attributes
        is shown below::

            { "plugin_ca_id1": {
                INFO_NAME : "CA name",
                INFO_DESCRIPTION : "CA user friendly description",
                INFO_CA_SIGNING_CERT : "base 64 encoded signing cert",
                INFO_INTERMEDIATES = "base 64 encoded certificate chain"
                INFO_EXPIRATION = "ISO formatted UTC datetime for when this"
                                  "data will become stale"
                }
            }

        """
        name = self.get_default_ca_name()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(days=CA_INFO_DEFAULT_EXPIRATION_DAYS))

        default_info = {
            INFO_NAME: name,
            INFO_DESCRIPTION: "Certificate Authority - {0}".format(name),
            INFO_EXPIRATION: expiration.isoformat()
        }

        signing_cert = self.get_default_signing_cert()
        if signing_cert is not None:
            default_info[INFO_CA_SIGNING_CERT] = signing_cert

        intermediates = self.get_default_intermediates()
        if intermediates is not None:
            default_info[INFO_INTERMEDIATES] = intermediates

        return {name: default_info}

    def supports_create_ca(self):
        """Returns whether the plugin supports on-the-fly generation of subCAs

        :return: boolean, True if supported, defaults to False
        """
        return False    # pragma: no cover

    def create_ca(self, ca_create_dto):
        """Creates a subordinate CA upon request

        This call should only be made if a plugin returns True for
        supports_create_ca().

        :param ca_create_dto:
            Data transfer object :class:`CACreateDTO` containing data
            required to generate a subordinate CA.  This data includes
            the subject DN of the new CA signing certificate, a name for
            the new CA and a reference to the CA that will issue the new
            subordinate CA's signing certificate,

        :return: ca_info:
            Dictionary containing the data needed to create a
            models.CertificateAuthority object
        """
        raise NotImplementedError    # pragma: no cover

    def delete_ca(self, ca_id):
        """Deletes a subordinate CA

        Like the create_ca call, this should only be made if the plugin
        returns Ture for supports_create_ca()

        :param ca_id: id for the CA as specified by the plugin
        :return: None
        """
        raise NotImplementedError   # pragma: no cover


class CACreateDTO(object):
    """Class that includes data needed to create a subordinate CA """

    def __init__(self, name=None, description=None, subject_dn=None,
                 parent_ca_id=None):
        """Creates a new CACreateDTO object.

        :param name: Name for the  subordinate CA
        :param description: Description for the subordinate CA
        :param subject_dn:
            Subject DN for the new subordinate CA's signing certificate
        :param parent_ca_id:
            ID of the CA which is supposed to sign the subordinate CA's
            signing certificate.  This is ID as known to the plugin
            (not the Barbican UUID)
        """
        self.name = name
        self.description = description
        self.subject_dn = subject_dn
        self.parent_ca_id = parent_ca_id


class CertificateStatus(object):
    """Defines statuses for certificate request process.

    In particular:

    CERTIFICATE_GENERATED - Indicates a certificate was created

    WAITING_FOR_CA - Waiting for Certificate authority (CA) to complete order

    CLIENT_DATA_ISSUE_SEEN - Problem was seen with client-provided data

    CA_UNAVAILABLE_FOR_REQUEST - CA was not available, will try again later

    REQUEST_CANCELED - The client or CA cancelled this order

    INVALID_OPERATION - Unexpected error seen processing order
    """

    CERTIFICATE_GENERATED = "certificate generated"
    WAITING_FOR_CA = "waiting for CA"
    CLIENT_DATA_ISSUE_SEEN = "client data issue seen"
    CA_UNAVAILABLE_FOR_REQUEST = "CA unavailable for request"
    REQUEST_CANCELED = "request canceled"
    INVALID_OPERATION = "invalid operation"


class ResultDTO(object):
    """Result data transfer object (DTO).

    An object of this type is returned by most certificate plugin methods, and
    is used to guide follow on processing and to provide status feedback to
    clients.
    """
    def __init__(self, status, status_message=None, certificate=None,
                 intermediates=None, retry_msec=RETRY_MSEC, retry_method=None):
        """Creates a new ResultDTO.

        :param status: Status for cert order
        :param status_message: Message to explain status type.
        :param certificate: Certificate returned from CA to be stored in
                            container
        :param intermediates: Intermediates to be stored in container
        :param retry_msec: Number of milliseconds to wait for retry
        :param retry_method: Method to be called for retry, if None then retry
                             the current method
        """
        self.status = status
        self.status_message = status_message
        self.certificate = certificate
        self.intermediates = intermediates
        self.retry_msec = int(retry_msec)
        self.retry_method = retry_method


class BarbicanMetaDTO(object):
    """Barbican meta data transfer object

    Information needed to process a certificate request that is not specified
    in the original request, and written by Barbican core, that is needed
    by the plugin to process requests.
    """

    def __init__(self, plugin_ca_id=None, generated_csr=None):
        """Creates a new BarbicanMetaDTO.

        :param plugin_ca_id: ca_id as known to the plugin
        :param generated_csr: csr generated in the stored-key case
        :return: BarbicanMetaDTO
        """
        self.plugin_ca_id = plugin_ca_id
        self.generated_csr = generated_csr


class CertificatePluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_args=(), invoke_kwargs={}):
        self.ca_repo = repos.get_ca_repository()
        super(CertificatePluginManager, self).__init__(
            conf.certificate.namespace,
            conf.certificate.enabled_certificate_plugins,
            invoke_on_load=False,  # Defer creating plugins to utility below.
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

        plugin_utils.instantiate_plugins(
            self, invoke_args, invoke_kwargs)

    def get_plugin(self, certificate_spec):
        """Gets a supporting certificate plugin.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: CertificatePluginBase plugin implementation
        """
        request_type = certificate_spec.get(
            REQUEST_TYPE,
            CertificateRequestType.CUSTOM_REQUEST)

        for plugin in plugin_utils.get_active_plugins(self):
            supported_request_types = plugin.supported_request_types()
            if request_type not in supported_request_types:
                continue

            if plugin.supports(certificate_spec):
                return plugin

        raise CertificatePluginNotFound()

    def get_plugin_by_name(self, plugin_name):
        """Gets a supporting certificate plugin.

        :param plugin_name: Name of the plugin to invoke
        :returns: CertificatePluginBase plugin implementation
        """
        for plugin in plugin_utils.get_active_plugins(self):
            if utils.generate_fullname_for(plugin) == plugin_name:
                return plugin
        raise CertificatePluginNotFound(plugin_name)

    def get_plugin_by_ca_id(self, ca_id):
        """Gets a plugin based on the ca_id.

        :param ca_id: id for CA in the CertificateAuthorities table
        :returns: CertificatePluginBase plugin implementation
        """
        ca = self.ca_repo.get(ca_id, suppress_exception=True)
        if not ca:
            raise CertificatePluginNotFoundForCAID(ca_id)

        return self.get_plugin_by_name(ca.plugin_name)

    def refresh_ca_table(self):
        """Refreshes the CertificateAuthority table."""
        updates_made = False
        for plugin in plugin_utils.get_active_plugins(self):
            plugin_name = utils.generate_fullname_for(plugin)
            cas, offset, limit, total = self.ca_repo.get_by_create_date(
                plugin_name=plugin_name,
                suppress_exception=True)
            if total < 1:
                # if no entries are found, then the plugin has not yet been
                # queried or that plugin's entries have expired.
                # Most of the time, this will be a no-op for plugins.
                self.update_ca_info(plugin)
                updates_made = True
        if updates_made:
            # commit to DB to avoid async issues with different threads
            repos.commit()

    def update_ca_info(self, cert_plugin):
        """Update the CA info for a particular plugin."""

        plugin_name = utils.generate_fullname_for(cert_plugin)
        try:
            new_ca_infos = cert_plugin.get_ca_info()
        except Exception as e:
            # The plugin gave an invalid CA, log and return
            LOG.error(u._LE("ERROR getting CA from plugin: %s"), e.message)
            return

        old_cas, offset, limit, total = self.ca_repo.get_by_create_date(
            plugin_name=plugin_name,
            suppress_exception=True,
            show_expired=True)

        if old_cas:
            for old_ca in old_cas:
                plugin_ca_id = old_ca.plugin_ca_id
                if plugin_ca_id not in new_ca_infos.keys():
                    # remove CAs that no longer exist
                    self._delete_ca(old_ca)
                else:
                    # update those that still exist
                    self.ca_repo.update_entity(
                        old_ca,
                        new_ca_infos[plugin_ca_id])
            old_ids = set([ca.plugin_ca_id for ca in old_cas])
        else:
            old_ids = set()

        new_ids = set(new_ca_infos.keys())

        # add new CAs
        add_ids = new_ids - old_ids
        for add_id in add_ids:
            try:
                self._add_ca(plugin_name, add_id, new_ca_infos[add_id])
            except Exception as e:
                # The plugin gave an invalid CA, log and continue
                LOG.error(u._LE("ERROR adding CA from plugin: %s"), e.message)

    def _add_ca(self, plugin_name, plugin_ca_id, ca_info):
        parsed_ca = dict(ca_info)
        parsed_ca['plugin_name'] = plugin_name
        parsed_ca['plugin_ca_id'] = plugin_ca_id
        new_ca = models.CertificateAuthority(parsed_ca)
        self.ca_repo.create_from(new_ca)

    def _delete_ca(self, ca):
        self.ca_repo.delete_entity_by_id(ca.id, None)


class _CertificateEventPluginManager(named.NamedExtensionManager,
                                     CertificateEventPluginBase):
    """Provides services for certificate event plugins.

    This plugin manager differs from others in that it implements the same
    contract as the plugins that it manages. This allows eventing operations
    to occur on all installed plugins (with this class acting as a composite
    plugin), rather than just eventing via an individual plugin.

    Each time this class is initialized it will load a new instance
    of each enabled plugin. This is undesirable, so rather than initializing a
    new instance of this class use the get_event_plugin_manager function
    at the module level.
    """
    def __init__(self, conf=CONF, invoke_args=(), invoke_kwargs={}):
        super(_CertificateEventPluginManager, self).__init__(
            conf.certificate_event.namespace,
            conf.certificate_event.enabled_certificate_event_plugins,
            invoke_on_load=False,  # Defer creating plugins to utility below.
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

        plugin_utils.instantiate_plugins(
            self, invoke_args, invoke_kwargs)

    def get_plugin_by_name(self, plugin_name):
        """Gets a supporting certificate event plugin.

        :returns: CertificateEventPluginBase plugin implementation
        """
        for plugin in plugin_utils.get_active_plugins(self):
            if utils.generate_fullname_for(plugin) == plugin_name:
                return plugin
        raise CertificateEventPluginNotFound(plugin_name)

    def notify_certificate_is_ready(
            self, project_id, order_ref, container_ref):
        self._invoke_certificate_plugins(
            'notify_certificate_is_ready',
            project_id, order_ref, container_ref)

    def notify_ca_is_unavailable(
            self, project_id, order_ref, error_msg, retry_in_msec):
        self._invoke_certificate_plugins(
            'notify_ca_is_unavailable',
            project_id, order_ref, error_msg, retry_in_msec)

    def _invoke_certificate_plugins(self, method, *args, **kwargs):
        """Invoke same function on plugins as calling function."""
        active_plugins = plugin_utils.get_active_plugins(self)

        if not active_plugins:
            raise CertificateEventPluginNotFound()

        for plugin in active_plugins:
            getattr(plugin, method)(*args, **kwargs)


def get_event_plugin_manager():
    global _EVENT_PLUGIN_MANAGER
    if _EVENT_PLUGIN_MANAGER:
        return _EVENT_PLUGIN_MANAGER
    _EVENT_PLUGIN_MANAGER = _CertificateEventPluginManager()
    return _EVENT_PLUGIN_MANAGER
