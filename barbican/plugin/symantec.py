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
Barbican certificate processing plugins and support.
"""
from barbican.plugin.interface import certificate_manager as cert


class SymantecCertificatePlugin(cert.CertificatePluginBase):
    """Symantec certificate plugin."""

    def issue_certificate_request(self, order_id, order_meta, plugin_meta):
        """Create the initial order with CA

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :returns: ResultDTO
        """
        successful, error_msg, can_retry = _ca_create_order(order_meta,
                                                            plugin_meta)

        if successful:
            return cert.ResultDTO(cert.CertificateStatus.WAITING_FOR_CA)
        elif can_retry:
            return cert.ResultDTO(
                cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message=error_msg
            )
        else:
            return cert.ResultDTO(cert.CertificateStatus.
                                  CA_UNAVAILABLE_FOR_REQUEST)

    def modify_certificate_request(self, order_id, order_meta, plugin_meta):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        """
        raise NotImplementedError  # pragma: no cover

    def cancel_certificate_request(self, order_id, order_meta, plugin_meta):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        """
        raise NotImplementedError  # pragma: no cover

    def check_certificate_status(self, order_id, order_meta, plugin_meta):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        """
        raise NotImplementedError  # pragma: no cover

    def supports(self, certificate_spec):
        """Returns a boolean indicating if the plugin supports the
        certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        #TODO(chellygel): Research what certificate types are supported by
        # symantec. Returning True for testing purposes
        return True


def _ca_create_order(self, order_meta, plugin_meta):
    """Creates an order with the Symantec CA.

    :returns: tuple with success, error message, and can retry
    """
    #TODO(jwood) Submit order to CA, get partner order id and
    #   then add to the plugin meta data.
    return True, None, None
