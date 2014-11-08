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

from barbican.common import hrefs
import barbican.common.utils as utils
from barbican.model import models
from barbican.plugin.interface import certificate_manager as cert
from barbican.plugin import resources as plugin

LOG = utils.getLogger(__name__)

# Order sub-status definitions
ORDER_STATUS_REQUEST_PENDING = models.OrderStatus(
    "cert_request_pending",
    "Request has been submitted to the CA.  "
    "Waiting for certificate to be generated"
)

ORDER_STATUS_CERT_GENERATED = models.OrderStatus(
    "cert_generated",
    "Certificate has been generated"
)

ORDER_STATUS_DATA_INVALID = models.OrderStatus(
    "cert_data_invalid",
    "CA rejected request data as invalid"
)

ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE = models.OrderStatus(
    "cert_ca_unavail_for_issue",
    "Unable to submit certificate request.  CA unavailable"
)

ORDER_STATUS_INVALID_OPERATION = models.OrderStatus(
    "cert_invalid_operation",
    "CA returned invalid operation"
)

ORDER_STATUS_INTERNAL_ERROR = models.OrderStatus(
    "cert_internal_error",
    "Internal error during certificate operations"
)

ORDER_STATUS_CA_UNAVAIL_FOR_CHECK = models.OrderStatus(
    "cert_ca_unavail_for_status_check",
    "Unable to get certificate request status.  CA unavailable."
)


def issue_certificate_request(order_model, project_model, repos):
    """Create the initial order with CA.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :param: repos - repos (to be removed)
    :returns: container_model - container with the relevant cert if
        the request has been completed.  None otherwise
    """
    container_model = None

    plugin_meta = _get_plugin_meta(order_model, repos)

    # Locate a suitable plugin to issue a certificate.
    cert_plugin = cert.CertificatePluginManager().get_plugin(order_model.meta)

    result = cert_plugin.issue_certificate_request(order_model.id,
                                                   order_model.meta,
                                                   plugin_meta)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta, repos)

    # Handle result
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        # TODO(alee-3): Add code to set sub status of "waiting for CA"
        _update_order_status(ORDER_STATUS_REQUEST_PENDING)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     repos, result, project_model,
                                     cert.RETRY_MSEC)
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        _update_order_status(ORDER_STATUS_CERT_GENERATED)
        container_model = _save_secrets(result, project_model, repos)
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        _update_order_status(ORDER_STATUS_DATA_INVALID)
        raise cert.CertificateStatusClientDataIssue(result.status_message)
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        # TODO(alee-3): set retry counter and error out if retries are exceeded
        _update_order_status(ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE)

        _schedule_issue_cert_request(cert_plugin, order_model, plugin_meta,
                                     repos, result, project_model,
                                     cert.ERROR_RETRY_MSEC)
        _notify_ca_unavailable(order_model, result)
    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        _update_order_status(ORDER_STATUS_INVALID_OPERATION)

        raise cert.CertificateStatusInvalidOperation(result.status_message)
    else:
        _update_order_status(ORDER_STATUS_INTERNAL_ERROR)
        raise cert.CertificateStatusNotSupported(result.status)

    return container_model


def check_certificate_request(order_model, project_model, plugin_name, repos):
    """Check the status of a certificate request with the CA.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :param: plugin_name - plugin the issued the certificate request
    :param; repos - repos (to be removed)
    :returns: container_model - container with the relevant cert if the
        request has been completed.  None otherwise.
    """
    container_model = None
    plugin_meta = _get_plugin_meta(order_model, repos)

    cert_plugin = cert.CertificatePluginManager().get_plugin_by_name(
        plugin_name)

    result = cert_plugin.check_certificate_request(order_model.id,
                                                   order_model.meta,
                                                   plugin_meta)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta, repos)

    # Handle result
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        _update_order_status(ORDER_STATUS_REQUEST_PENDING)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     repos, result, project_model,
                                     cert.RETRY_MSEC)
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        _update_order_status(ORDER_STATUS_CERT_GENERATED)
        container_model = _save_secrets(result, project_model, repos)
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        _update_order_status(cert.ORDER_STATUS_DATA_INVALID)
        raise cert.CertificateStatusClientDataIssue(result.status_message)
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        # TODO(alee-3): decide what to do about retries here
        _update_order_status(ORDER_STATUS_CA_UNAVAIL_FOR_CHECK)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     repos, result, project_model,
                                     cert.ERROR_RETRY_MSEC)

    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        _update_order_status(ORDER_STATUS_INVALID_OPERATION)
        raise cert.CertificateStatusInvalidOperation(result.status_message)
    else:
        _update_order_status(ORDER_STATUS_INTERNAL_ERROR)
        raise cert.CertificateStatusNotSupported(result.status)

    return container_model


def modify_certificate_request(order_model, updated_meta, repos):
    """Update the order with CA."""
    # TODO(chellygel): Add the modify certificate request logic.
    LOG.debug('in modify_certificate_request')
    raise NotImplementedError  # pragma: no cover


def _schedule_cert_retry_task(cert_result_dto, cert_plugin, order_model,
                              plugin_meta,
                              retry_method=None,
                              retry_object=None,
                              retry_time=None,
                              retry_args=None):
    if cert_result_dto.retry_msec > 0:
        retry_time = cert_result_dto.retry_msec

    if cert_result_dto.retry_method:
        retry_method = cert_result_dto.retry_method
        retry_object = utils.generate_fullname_for(cert_plugin)
        retry_args = [order_model.id, order_model.meta, plugin_meta]

    _schedule_retry_task(retry_object, retry_method, retry_time, retry_args)


def _schedule_issue_cert_request(cert_plugin, order_model, plugin_meta, repos,
                                 cert_result_dto, project_model, retry_time):
    retry_args = [order_model,
                  project_model,
                  repos]
    _schedule_cert_retry_task(
        cert_result_dto, cert_plugin, order_model, plugin_meta,
        retry_method="issue_certificate_request",
        retry_object="barbican.tasks.certificate_resources",
        retry_time=retry_time,
        retry_args=retry_args)


def _schedule_check_cert_request(cert_plugin, order_model, plugin_meta, repos,
                                 cert_result_dto, project_model, retry_time):
    retry_args = [order_model,
                  project_model,
                  utils.generate_fullname_for(cert_plugin),
                  repos]
    _schedule_cert_retry_task(
        cert_result_dto, cert_plugin, order_model, plugin_meta,
        retry_method="check_certificate_request",
        retry_object="barbican.tasks.certificate_resources",
        retry_time=retry_time,
        retry_args=retry_args)


def _update_order_status(order_status):
    # TODO(alee-3): add code to set order substatus, substatus message
    # and save the order.  most likely this call methods defined in Order.
    pass


def _schedule_retry_task(retry_object, retry_method, retry_time, args):
    # TODO(alee-3): Implement this method - here or elsewhere .
    pass


def _get_plugin_meta(order_model, repos):
    if order_model:
        return repos.order_plugin_meta_repo.get_metadata_for_order(
            order_model.id)
    else:
        return dict()


def _notify_ca_unavailable(order_model, result):
    """Notify observer(s) that the CA was unavailable at this time."""
    cert.EVENT_PLUGIN_MANAGER.notify_ca_is_unavailable(
        order_model.tenant_id,
        hrefs.convert_order_to_href(order_model.id),
        result.status_message,
        result.retry_msec)


def _save_plugin_metadata(order_model, plugin_meta, repos):
    """Add plugin metadata to an order."""

    if not isinstance(plugin_meta, dict):
        plugin_meta = dict()

    repos.order_plugin_meta_repo.save(plugin_meta, order_model)


def _save_secrets(result, project_model, repos):
    cert_secret_model, transport_key_model = plugin.store_secret(
        unencrypted_raw=result.certificate,
        content_type_raw='text/plain',
        content_encoding='base64',
        spec={},
        secret_model=None,
        project_model=project_model,
        repos=repos)

    # save the certificate chain as a secret.
    if result.intermediates:
        intermediates_secret_model, transport_key_model = plugin.store_secret(
            unencrypted_raw=result.intermediates,
            content_type_raw='text/plain',
            content_encoding='base64',
            spec={},
            secret_model=None,
            project_model=project_model,
            repos=repos
        )
    else:
        intermediates_secret_model = None

    container_model = models.Container()
    container_model.type = "certificate"
    container_model.status = models.States.ACTIVE
    container_model.tenant_id = project_model.id
    repos.container_repo.create_from(container_model)

    # create container_secret for certificate
    new_consec_assoc = models.ContainerSecret()
    new_consec_assoc.name = 'certificate'
    new_consec_assoc.container_id = container_model.id
    new_consec_assoc.secret_id = cert_secret_model.id
    repos.container_secret_repo.create_from(new_consec_assoc)

    if intermediates_secret_model:
        # create container_secret for intermediate certs
        new_consec_assoc = models.ContainerSecret()
        new_consec_assoc.name = 'intermediates'
        new_consec_assoc.container_id = container_model.id
        new_consec_assoc.secret_id = intermediates_secret_model.id
        repos.container_secret_repo.create_from(new_consec_assoc)

    return container_model
