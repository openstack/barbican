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

from barbican.plugin.interface import certificate_manager as cert


def issue_certificate_request(order_model, repos):
    """Create the initial order with CA."""

    plugin_meta = _get_plugin_meta(order_model)

    # Locate a suitable plugin to issue a certificate.
    cert_plugin = cert.CertificatePluginManager().get_plugin()

    result = cert_plugin.issue_certificate_request(order_model.id,
                                                   order_model.meta,
                                                   plugin_meta)
    # Handle result
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        #TODO(chellygel): Logic for retry
        pass
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        #TODO(chellygel): Logic for store cert in container
        pass
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        #TODO(chellygel): Logic for notify client of issue
        pass
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        #TODO(chellygel): Logic for notify client of CA unavailable and retry
        pass
    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        #TODO(chellygel): Logic for notify client of CA conflict
        pass
    else:
        raise cert.CertificateStatusNotSupported(result.status)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta, repos)


def _get_plugin_meta(order_model):
    if order_model:
        meta_dict = dict((k, v.value) for (k, v) in
                         order_model.order_plugin_meta.items())
        return meta_dict
    else:
        return dict()


def _save_plugin_metadata(order_model, plugin_meta, repos):
    """Add plugin metadata to an order."""

    if not isinstance(plugin_meta, dict):
        plugin_meta = dict()

    repos.order_plugin_meta_repo.save(plugin_meta, order_model)
