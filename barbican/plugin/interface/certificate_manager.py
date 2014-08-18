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

from oslo.config import cfg
import six
from stevedore import named

from barbican.common import exception
import barbican.common.utils as utils
from barbican.openstack.common import gettextutils as u


CONF = cfg.CONF

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

CA_PLUGIN_TYPE_DOGTAG = "dogtag"
CA_PLUGIN_TYPE_SYMANTEC = "symantec"

# fields to distinguish CA types and subject key identifiers
CA_TYPE = "ca_type"
CA_SUBJECT_KEY_IDENTIFIER = "ca_subject_key_identifier"


class CertificatePluginNotFound(exception.BarbicanException):
    """Raised when no certificate plugin supporting a request is available."""
    def __init__(self, plugin_name=None):
        if plugin_name:
            message = u._(
                "Certificate plugin \"{0}\""
                " not found or configured.").format(plugin_name)
        else:
            message = u._("Certificate plugin not found or configured.")
        super(CertificatePluginNotFound, self).__init__(message)


class CertificateEventPluginNotFound(exception.BarbicanException):
    """Raised with no certificate event plugin supporting request."""
    def __init__(self, plugin_name=None):
        if plugin_name:
            message = u._(
                "Certificate event plugin "
                "\"{0}\" not found or configured.").format(plugin_name)
        else:
            message = u._("Certificate event plugin not found or configured.")
        super(CertificateEventPluginNotFound, self).__init__(message)


class CertificateStatusNotSupported(exception.BarbicanException):
    """Raised when cert status returned is unknown."""
    def __init__(self, status):
        super(CertificateStatusNotSupported, self).__init__(
            u._("Certificate status of '{0}' not supported").format(status))
        self.status = status


class CertificateGeneralException(exception.BarbicanException):
    """Raised when a system fault has occurred."""
    def __init__(self, reason=u._('Unknown')):
        super(CertificateGeneralException, self).__init__(
            u._('Problem seen during certificate processing - '
                'Reason: {0}').format(reason)
        )
        self.reason = reason


class CertificateStatusClientDataIssue(exception.BarbicanException):
    """Raised when the CA has encountered an issue with request data."""
    def __init__(self, reason=u._('Unknown')):
        super(CertificateStatusClientDataIssue, self).__init__(
            u._('Problem with data in certificate request - '
                'Reason: {0}').format(reason)
        )
        self.reason = reason


class CertificateStatusInvalidOperation(exception.BarbicanException):
    """Raised when the CA has encountered an issue with request data."""
    def __init__(self, reason=u._('Unknown')):
        super(CertificateStatusInvalidOperation, self).__init__(
            u._('Invalid operation requested - '
                'Reason: {0}').format(reason)
        )
        self.reason = reason


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

        :param project_id: Project/tenant ID associated with this certificate
        :param order_ref: HATEOS reference URI to the submitted Barbican Order
        :param container_ref: HATEOS reference URI to the Container storing
               the certificate
        :returns: None
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def notify_ca_is_unavailable(
            self, project_id, order_ref, error_msg, retry_in_msec):
        """Notify that the certificate authority (CA) isn't available.

        :param project_id: Project/tenant ID associated with this order
        :param order_ref: HATEOS reference URI to the submitted Barbican Order
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
    def issue_certificate_request(self, order_id, order_meta, plugin_meta):
        """Create the initial order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def modify_certificate_request(self, order_id, order_meta, plugin_meta):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def cancel_certificate_request(self, order_id, order_meta, plugin_meta):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def check_certificate_status(self, order_id, order_meta, plugin_meta):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf
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


class CertificateStatus(object):
    """Defines statuses for certificate request process."""

    CERTIFICATE_GENERATED = "certificate generated"
    WAITING_FOR_CA = "waiting for CA"
    CLIENT_DATA_ISSUE_SEEN = "client data issue seen"
    CA_UNAVAILABLE_FOR_REQUEST = "CA unavailable for request"
    REQUEST_CANCELED = "request canceled"
    INVALID_OPERATION = "invalid operation"


class ResultDTO(object):
    """This object is the result data transfer object (DTO)."""
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


class CertificatePluginManager(named.NamedExtensionManager):
    def __init__(self, conf=CONF, invoke_on_load=True,
                 invoke_args=(), invoke_kwargs={}):
        super(CertificatePluginManager, self).__init__(
            conf.certificate.namespace,
            conf.certificate.enabled_certificate_plugins,
            invoke_on_load=invoke_on_load,
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

    def get_plugin(self, certificate_spec):
        """Gets a supporting certificate plugin.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: CertificatePluginBase plugin implementation
        """
        for ext in self.extensions:
            if ext.obj.supports(certificate_spec):
                return ext.obj
        raise CertificatePluginNotFound()

    def get_plugin_by_name(self, plugin_name):
        """Gets a supporting certificate plugin.

        :param plugin_name: Name of the plugin to invoke
        :returns: CertificatePluginBase plugin implementation
        """
        for ext in self.extensions:
            if utils.generate_fullname_for(ext.obj) == plugin_name:
                return ext.obj
        raise CertificatePluginNotFound(plugin_name)


class _CertificateEventPluginManager(named.NamedExtensionManager,
                                     CertificateEventPluginBase):
    """Provides services for certificate event plugins.

    This plugin manager differs from others in that it implements the same
    contract as the plugins that it manages. This allows eventing operations
    to occur on all installed plugins (with this class acting as a composite
    plugin), rather than just eventing via an individual plugin.

    Each time this class is initialized it will load a new instance
    of each enabled plugin. This is undesirable, so rather than initializing a
    new instance of this class use the EVENT_PLUGIN_MANAGER at the module
    level.
    """
    def __init__(self, conf=CONF, invoke_on_load=True,
                 invoke_args=(), invoke_kwargs={}):
        super(_CertificateEventPluginManager, self).__init__(
            conf.certificate_event.namespace,
            conf.certificate_event.enabled_certificate_event_plugins,
            invoke_on_load=invoke_on_load,
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

    def get_plugin_by_name(self, plugin_name):
        """Gets a supporting certificate event plugin.

        :returns: CertficiateEventPluginBase plugin implementation
        """
        for ext in self.extensions:
            if utils.generate_fullname_for(ext.obj) == plugin_name:
                return ext.obj
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
        if len(self.extensions) < 1:
            raise CertificateEventPluginNotFound()

        for ext in self.extensions:
            getattr(ext.obj, method)(*args, **kwargs)


EVENT_PLUGIN_MANAGER = _CertificateEventPluginManager()
