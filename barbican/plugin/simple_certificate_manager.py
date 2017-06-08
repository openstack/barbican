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
from barbican.plugin.interface import certificate_manager as cert

LOG = utils.getLogger(__name__)


MSEC_UNTIL_CHECK_STATUS = 5000


class SimpleCertificatePlugin(cert.CertificatePluginBase):
    """Simple/default certificate plugin."""

    def get_default_ca_name(self):
        return "Simple CA"

    def get_default_signing_cert(self):
        return "XXXXXXXXXXXXXXXXX"

    def get_default_intermediates(self):
        return "YYYYYYYYYYYYYYYY"

    def issue_certificate_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Create the initial order with CA

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info('Invoking issue_certificate_request()')
        return cert.ResultDTO(
            cert.CertificateStatus.WAITING_FOR_CA,
            retry_msec=MSEC_UNTIL_CHECK_STATUS)

    def modify_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info('Invoking modify_certificate_request()')
        return cert.ResultDTO(cert.CertificateStatus.WAITING_FOR_CA)

    def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info('Invoking cancel_certificate_request()')
        return cert.ResultDTO(cert.CertificateStatus.REQUEST_CANCELED)

    def check_certificate_status(self, order_id, order_meta, plugin_meta,
                                 barbican_meta_dto):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        :returns: A :class:`ResultDTO` instance containing the result
                  populated by the plugin implementation
        :rtype: :class:`ResultDTO`
        """
        LOG.info('Invoking check_certificate_status()')
        return cert.ResultDTO(cert.CertificateStatus.CERTIFICATE_GENERATED)

    def supports(self, certificate_spec):
        """Indicates whether the plugin supports the certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        return True

    def supported_request_types(self):
        """Returns the request types supported by this plugin.

        :returns: dict containing Barbican-core defined request types
                  supported by this plugin.
        """
        return [cert.CertificateRequestType.CUSTOM_REQUEST,
                cert.CertificateRequestType.SIMPLE_CMC_REQUEST,
                cert.CertificateRequestType.FULL_CMC_REQUEST,
                cert.CertificateRequestType.STORED_KEY_REQUEST]


class SimpleCertificateEventPlugin(cert.CertificateEventPluginBase):
    """Simple/default certificate event plugin."""

    def notify_certificate_is_ready(
            self, project_id, order_ref, container_ref):
        """Notify that a certificate has been generated and is ready to use.

        :param project_id: Project ID associated with this certificate
        :param order_ref: HATEOAS reference URI to the submitted Barbican Order
        :param container_ref: HATEOAS reference URI to the Container storing
               the certificate
        :returns: None
        """
        LOG.info('Invoking notify_certificate_is_ready()')

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
        LOG.info('Invoking notify_ca_is_unavailable()')
