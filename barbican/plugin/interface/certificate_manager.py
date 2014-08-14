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
from barbican.openstack.common import gettextutils as u


CONF = cfg.CONF
DEFAULT_PLUGIN_NAMESPACE = 'barbican.certificate.plugin'
#TODO(chellygel): Create a default 'dummy' plugin for certificates.
DEFAULT_PLUGINS = []

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

RETRY_MSEC = 3600000


class CertificatePluginNotFound(exception.BarbicanException):
    """Raised when no plugins are installed."""
    message = u._("Certificate plugin not found.")


class CertificateStatusNotSupported(exception.BarbicanException):
    """Raised when cert status returned is unknown."""
    def __init__(self, status):
        super(CertificateStatusNotSupported, self).__init__(
            u._("Certificate status of '{0}' not supported").format(status))
        self.status = status


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
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def supports(self, certificate_spec):
        """Returns a boolean indicating if the plugin supports the
        certificate type.

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
        self.retry_msec = retry_msec
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
        :returns: CertficiatePluginBase plugin implementation
        """
        for ext in self.extensions:
            if ext.obj.supports(certificate_spec):
                return ext.obj
        raise CertificatePluginNotFound()
