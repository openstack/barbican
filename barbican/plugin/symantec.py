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
from requests import exceptions as request_exceptions

from oslo.config import cfg
from symantecssl.core import Symantec
from symantecssl import exceptions as symantec_exceptions

from barbican.openstack.common import gettextutils as u
from barbican.plugin.interface import certificate_manager as cert

CONF = cfg.CONF

symantec_plugin_group = cfg.OptGroup(name='symantec_plugin',
                                     title='Symantec Plugin Options')

symantec_plugin_opts = [
    cfg.StrOpt('username',
               help=u._('Symantec username for authentication')),
    cfg.StrOpt('password',
               help=u._('Symantec password for authentication')),
    cfg.StrOpt('url',
               help=u._('Domain of Symantec API'))
]

CONF.register_group(symantec_plugin_group)
CONF.register_opts(symantec_plugin_opts, group=symantec_plugin_group)


class SymantecCertificatePlugin(cert.CertificatePluginBase):
    """Symantec certificate plugin."""

    def __init__(self, conf=CONF):
        self.username = conf.symantec_plugin.username
        if self.username == None:
            raise ValueError(u._("username is required"))

        self.password = conf.symantec_plugin.password
        if self.password == None:
            raise ValueError(u._("password is required"))

        self.url = conf.symantec_plugin.url
        if self.url == None:
            raise ValueError(u._("url is required"))

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
    """Creates an order with the Symantec CA. The PartnerOrderId
    and GeoTrustOrderId are returned and stored in plugin_meta.
    PartnerCode and ProductCode are also stored in plugin_meta for
    future use.

    All required order parameters must be stored as a dict in
    order_meta.
    Required fields are:
    partnerCode, productCode, partnerOrderId, organizationName,
    addressLine1, city, region, postalCode, country, organizationPhone
    validityPeriod, serverCount, webServerType, adminContactFirstName,
    adminContactLastName, adminContactPhone, adminContactEmail,
    adminContactTitle, adminContactAddressLine1, adminContactCity,
    adminContactRegion, adminContactPostalCode, adminContactCountry, bill
    and tech contact info, and csr.

    Optional Parameters: techSameAsAdmin, billSameAsAdmin, more options can be
    found in Symantec's API docs.

    :returns: tuple with success, error message, and can retry
    """

    api = Symantec(self.username, self.password, self.url)

    try:
        order_data = api.order(**order_meta)

        # GeotrustOrderId is used to handle emails from Symantec.
        # PartnerCode and ProductCode are being stored in plugin_meta for
        # convenience when calling _ca_get_order_status, _ca_modify_order, etc.
        plugin_meta["GeotrustOrderID"] = order_data["GeotrustOrderID"]
        plugin_meta["PartnerOrderID"] = order_data["PartnerOrderID"]
        plugin_meta["PartnerCode"] = order_meta["OrderDetails"]["PartnerCode"]
        plugin_meta["ProductCode"] = order_meta["OrderDetails"]["ProductCode"]
        return True, None, False
    except symantec_exceptions.SymantecError as e:
        return False, e, False
    except request_exceptions.RequestException as e:
        return False, e, True


def _ca_get_order_status(self, plugin_meta):
    """Sends a request to the Symantec CA for details on an order.

    Parameters needed for GetOrderByPartnerOrderID:
    plugin_meta parameters: partnerOrderId, partnerCode

    If the order is complete, the Certificate is returned as a string.
    returns: tuple with success, error message, can retry,
             and the certificate (if available).
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "partnerOrderId": plugin_meta["PartnerOrderID"],
        "partnerCode": plugin_meta["PartnerCode"],
        "returnCertificateInfo": "TRUE",
        "returnFulfillment": "TRUE",
        "returnCaCerts": "TRUE",
    }

    try:
        order_data = api.get_order_by_partner_order_id(**order_details)
        if order_data["OrderInfo"]["OrderState"] == "COMPLETED":
            ca = order_data["Fulfillment"]["CACertificates"]["CACertificate"]
            return True, None, False, ca["CACert"]
        return True, None, False, None
    except symantec_exceptions.SymantecError as e:
        return False, e, False, None
    except request_exceptions.RequestException as e:
        return False, e, True, None


def _ca_modify_order(self, order_meta, plugin_meta):
    """Sends a request to the Symantec CA to modify an order.
    Parameters needed for modifyOrder:
        partnerorderid - Needed to specify order
        partnercode - Needed to specify order
        productcode - Needed to specify order

    Also need a dict, order_meta with the parameters/values to modify.

    returns: tuple with success, error message, and can retry.
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "partnerOrderId": plugin_meta["PartnerOrderID"],
        "partnerCode": plugin_meta["PartnerCode"],
        "productCode": plugin_meta["ProductCode"],
    }

    order_details.update(order_meta)

    try:
        api.validate_order_parameters(**order_details)
        return True, None, False
    except symantec_exceptions.SymantecError as e:
        return False, e, False
    except request_exceptions.RequestException as e:
        return False, e, True


def _ca_cancel_order(self, plugin_meta):
    """Sends a request to the Symantec CA to cancel an order.
    Parameters needed for modifyOrder:
        partnerorderid - Needed to specify order
        partnercode - Needed to specify order
        productcode - Needed to specify order

    returns: tuple with success, error message, and can retry.
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "partnerOrderId": plugin_meta["PartnerOrderID"],
        "partnerCode": plugin_meta["PartnerCode"],
        "productCode": plugin_meta["ProductCode"],
        "modifyOrderOperation": "CANCEL",
    }

    try:
        api.modify_order(**order_details)
        return True, None, False
    except symantec_exceptions.SymantecError as e:
        return False, e, False
    except request_exceptions.RequestException as e:
        return False, e, True
