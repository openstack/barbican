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
from oslo_config import cfg
from requests import exceptions as request_exceptions
from symantecssl.core import Symantec
from symantecssl import exceptions as symantec_exceptions

from barbican.common import config
from barbican import i18n as u
from barbican.plugin.interface import certificate_manager as cert

CONF = config.new_config()

symantec_plugin_group = cfg.OptGroup(name='symantec_plugin',
                                     title='Symantec Plugin Options')

symantec_plugin_opts = [
    cfg.StrOpt('username',
               help=u._('Symantec username for authentication')),
    cfg.StrOpt('password',
               help=u._('Symantec password for authentication'),
               secret=True),
    cfg.StrOpt('url',
               help=u._('Domain of Symantec API'))
]

CONF.register_group(symantec_plugin_group)
CONF.register_opts(symantec_plugin_opts, group=symantec_plugin_group)
config.parse_args(CONF)


class SymantecCertificatePlugin(cert.CertificatePluginBase):
    """Symantec certificate plugin."""

    def __init__(self, conf=CONF):
        self.username = conf.symantec_plugin.username
        self.password = conf.symantec_plugin.password
        self.url = conf.symantec_plugin.url

        if self.username is None:
            raise ValueError(u._("username is required"))

        if self.password is None:
            raise ValueError(u._("password is required"))

        if self.url is None:
            raise ValueError(u._("url is required"))

    def get_default_ca_name(self):
        return "Symantec CA"

    def get_default_signing_cert(self):
        # TODO(chellygel) Add code to get the signing cert
        return None

    def get_default_intermediates(self):
        # TODO(chellygel) Add code to get the cert chain
        return None

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
        :returns: ResultDTO
        """
        successful, error_msg, can_retry = _ca_create_order(order_meta,
                                                            plugin_meta)

        status = cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST
        message = None

        if successful:
            status = cert.CertificateStatus.WAITING_FOR_CA
        elif can_retry:
            status = cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN
            message = error_msg

        return cert.ResultDTO(status=status, status_message=message)

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
        """
        raise NotImplementedError  # pragma: no cover

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
        """
        raise NotImplementedError  # pragma: no cover

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
        """
        raise NotImplementedError  # pragma: no cover

    def supports(self, certificate_spec):
        """Indicates if the plugin supports the certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        # TODO(chellygel): Research what certificate types are supported by
        # symantec. Returning True for testing purposes
        return True


def _ca_create_order(self, order_meta, plugin_meta):
    """Creates an order with the Symantec CA.

    The PartnerOrderId and GeoTrustOrderId are returned and stored in
    plugin_meta. PartnerCode and ProductCode are also stored in plugin_meta
    for future use.

    All required order parameters must be stored as a dict in
    order_meta.
    Required fields are:
    PartnerCode, ProductCode, PartnerOrderId, OrganizationName,
    AddressLine1, City, Region, PostalCode, Country, OrganizationPhone
    ValidityPeriod, ServerCount, WebServerType, AdminContactFirstName,
    AdminContactLastName, AdminContactPhone, AdminContactEmail,
    AdminContactTitle, AdminContactAddressLine1, AdminContactCity,
    AdminContactRegion, AdminContactPostalCode, AdminContactCountry,
    BillingContact*,  TechContact*, and CSR.

    *The Billing and Tech contact information follows the same convention
    as the AdminContact fields.

    Optional Parameters: TechSameAsAdmin, BillSameAsAdmin, more options can be
    found in Symantec's API docs. Contact Symantec for the API document.

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
    plugin_meta parameters: PartnerOrderId, PartnerCode

    If the order is complete, the Certificate is returned as a string.
    returns: tuple with success, error message, can retry,
             and the certificate (if available).
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "PartnerOrderID": plugin_meta["PartnerOrderID"],
        "PartnerCode": plugin_meta["PartnerCode"],
        "ReturnCertificateInfo": "TRUE",
        "ReturnFulfillment": "TRUE",
        "ReturnCaCerts": "TRUE",
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
        PartnerOrderID - Needed to specify order
        PartnerCode - Needed to specify order
        ProductCode - Needed to specify order

    Also need a dict, order_meta with the parameters/values to modify.

    returns: tuple with success, error message, and can retry.
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "PartnerOrderID": plugin_meta["PartnerOrderID"],
        "PartnerCode": plugin_meta["PartnerCode"],
        "ProductCode": plugin_meta["ProductCode"],
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
        PartnerOrderID - Needed to specify order
        PartnerCode - Needed to specify order
        ProductCode - Needed to specify order

    returns: tuple with success, error message, and can retry.
    """
    api = Symantec(self.username, self.password, self.url)

    order_details = {
        "PartnerOrderID": plugin_meta["PartnerOrderID"],
        "PartnerCode": plugin_meta["PartnerCode"],
        "ProductCode": plugin_meta["ProductCode"],
        "ModifyOrderOperation": "CANCEL",
    }

    try:
        api.modify_order(**order_details)
        return True, None, False
    except symantec_exceptions.SymantecError as e:
        return False, e, False
    except request_exceptions.RequestException as e:
        return False, e, True
