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
Default implementation of Barbican certificate processing plugins and support.
"""
from barbican.common import utils
from barbican.openstack.common import gettextutils as u
from barbican.plugin.interface import certificate_manager as cert

LOG = utils.getLogger(__name__)


class SimpleCertificatePlugin(cert.CertificatePluginBase):
    """Simple/default certificate plugin."""

    def issue_certificate_request(self, order_id, order_meta, plugin_meta):
        """Create the initial order with CA

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info(u._('Invoking issue_certificate_request()'))
        return cert.ResultDTO(cert.CertificateStatus.WAITING_FOR_CA)

    def modify_certificate_request(self, order_id, order_meta, plugin_meta):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info(u._('Invoking modify_certificate_request()'))
        return cert.ResultDTO(cert.CertificateStatus.WAITING_FOR_CA)

    def cancel_certificate_request(self, order_id, order_meta, plugin_meta):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info(u._('Invoking cancel_certificate_request()'))
        return cert.ResultDTO(cert.CertificateStatus.REQUEST_CANCELED)

    def check_certificate_status(self, order_id, order_meta, plugin_meta):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info(u._('Invoking check_certificate_status()'))
        return cert.ResultDTO(cert.CertificateStatus.WAITING_FOR_CA)

    def supports(self, certificate_spec):
        """Returns a boolean indicating if the plugin supports the
        certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        return True


class SimpleCertificateEventPlugin(cert.CertificateEventPluginBase):
    """Simple/default certificate event plugin."""

    def notify_certificate_is_ready(
            self, project_id, order_ref, container_ref):
        """Notify that a certificate has been generated and is ready to use.

        :param project_id: Project/tenant ID associated with this certificate
        :param order_ref: HATEOS reference URI to the submitted Barbican Order
        :param container_ref: HATEOS reference URI to the Container storing
               the certificate
        :returns: None
        """
        LOG.info(u._('Invoking notify_certificate_is_ready()'))

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
        LOG.info(u._('Invoking notify_ca_is_unavailable()'))
