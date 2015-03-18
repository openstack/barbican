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

import ldap
from OpenSSL import crypto

from barbican.common import exception as excep
from barbican.common import hrefs
import barbican.common.utils as utils
from barbican.model import models
from barbican.model import repositories as repos
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


def issue_certificate_request(order_model, project_model):
    """Create the initial order with CA.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :returns: container_model - container with the relevant cert if
        the request has been completed.  None otherwise
    """
    container_model = None

    plugin_meta = _get_plugin_meta(order_model)
    barbican_meta_dto = cert.BarbicanMetaDTO()

    # refresh the CA table.  This is mostly a no-op unless the entries
    # for a plugin are expired.
    cert.CertificatePluginManager(repos).refresh_ca_table()

    ca_id = _get_ca_id(order_model.meta, project_model.id)
    if ca_id:
        barbican_meta_dto.plugin_ca_id = ca_id
        cert_plugin = cert.CertificatePluginManager().get_plugin_by_ca_id(
            ca_id)
    else:
        cert_plugin = cert.CertificatePluginManager().get_plugin(
            order_model.meta)

    request_type = order_model.meta.get(cert.REQUEST_TYPE)
    if request_type == cert.CertificateRequestType.STORED_KEY_REQUEST:
        csr = order_model.order_barbican_metadata.get('generated_csr')
        if csr is None:
            csr = _generate_csr(order_model)
            order_model.order_barbican_metadata['generated_csr'] = csr
            order_model.save()
        barbican_meta_dto.generated_csr = csr

    result = cert_plugin.issue_certificate_request(order_model.id,
                                                   order_model.meta,
                                                   plugin_meta,
                                                   barbican_meta_dto)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta)

    # Handle result
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        # TODO(alee-3): Add code to set sub status of "waiting for CA"
        _update_order_status(ORDER_STATUS_REQUEST_PENDING)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     result, project_model, cert.RETRY_MSEC)
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        _update_order_status(ORDER_STATUS_CERT_GENERATED)
        container_model = _save_secrets(result, project_model)
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        _update_order_status(ORDER_STATUS_DATA_INVALID)
        raise cert.CertificateStatusClientDataIssue(result.status_message)
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        # TODO(alee-3): set retry counter and error out if retries are exceeded
        _update_order_status(ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE)

        _schedule_issue_cert_request(cert_plugin, order_model, plugin_meta,
                                     result, project_model,
                                     cert.ERROR_RETRY_MSEC)
        _notify_ca_unavailable(order_model, result)
    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        _update_order_status(ORDER_STATUS_INVALID_OPERATION)

        raise cert.CertificateStatusInvalidOperation(result.status_message)
    else:
        _update_order_status(ORDER_STATUS_INTERNAL_ERROR)
        raise cert.CertificateStatusNotSupported(result.status)

    return container_model


def check_certificate_request(order_model, project_model, plugin_name):
    """Check the status of a certificate request with the CA.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :param: plugin_name - plugin the issued the certificate request
    :returns: container_model - container with the relevant cert if the
        request has been completed.  None otherwise.
    """
    container_model = None
    plugin_meta = _get_plugin_meta(order_model)
    barbican_meta_dto = cert.BarbicanMetaDTO()

    cert_plugin = cert.CertificatePluginManager().get_plugin_by_name(
        plugin_name)

    result = cert_plugin.check_certificate_request(order_model.id,
                                                   order_model.meta,
                                                   plugin_meta,
                                                   barbican_meta_dto)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta)

    # Handle result
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        _update_order_status(ORDER_STATUS_REQUEST_PENDING)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     result, project_model,
                                     cert.RETRY_MSEC)
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        _update_order_status(ORDER_STATUS_CERT_GENERATED)
        container_model = _save_secrets(result, project_model)
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        _update_order_status(cert.ORDER_STATUS_DATA_INVALID)
        raise cert.CertificateStatusClientDataIssue(result.status_message)
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        # TODO(alee-3): decide what to do about retries here
        _update_order_status(ORDER_STATUS_CA_UNAVAIL_FOR_CHECK)
        _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                     result, project_model,
                                     cert.ERROR_RETRY_MSEC)

    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        _update_order_status(ORDER_STATUS_INVALID_OPERATION)
        raise cert.CertificateStatusInvalidOperation(result.status_message)
    else:
        _update_order_status(ORDER_STATUS_INTERNAL_ERROR)
        raise cert.CertificateStatusNotSupported(result.status)

    return container_model


def modify_certificate_request(order_model, updated_meta):
    """Update the order with CA."""
    # TODO(chellygel): Add the modify certificate request logic.
    LOG.debug('in modify_certificate_request')
    raise NotImplementedError  # pragma: no cover


def _get_ca_id(order_meta, project_id):
    ca_id = order_meta.get(cert.CA_ID)
    if ca_id:
        return ca_id

    preferred_ca_repository = repos.get_preferred_ca_repository()
    cas, offset, limit, total = preferred_ca_repository.get_by_create_date(
        project_id=project_id)
    if total > 0:
        return cas[0].ca_id

    global_ca = preferred_ca_repository.get_global_preferred_ca()
    if global_ca:
        return global_ca.ca_id

    return None


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


def _schedule_issue_cert_request(cert_plugin, order_model, plugin_meta,
                                 cert_result_dto, project_model, retry_time):
    retry_args = [order_model,
                  project_model]
    _schedule_cert_retry_task(
        cert_result_dto, cert_plugin, order_model, plugin_meta,
        retry_method="issue_certificate_request",
        retry_object="barbican.tasks.certificate_resources",
        retry_time=retry_time,
        retry_args=retry_args)


def _schedule_check_cert_request(cert_plugin, order_model, plugin_meta,
                                 cert_result_dto, project_model, retry_time):
    retry_args = [order_model,
                  project_model,
                  utils.generate_fullname_for(cert_plugin)]
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


def _get_plugin_meta(order_model):
    if order_model:
        order_plugin_meta_repo = repos.get_order_plugin_meta_repository()
        return order_plugin_meta_repo.get_metadata_for_order(order_model.id)
    else:
        return {}


def _generate_csr(order_model):
    """Generate a CSR from the public key.

    :param: order_model - order for the request
    :return: CSR (certificate signing request) in PEM format
    :raise: :class:`StoredKeyPrivateKeyNotFound` if private key not found
            :class:`StoredKeyContainerNotFound` if container not found
    """
    container_ref = order_model.meta.get('container_ref')

    # extract container_id as the last part of the URL
    container_id = container_ref.rsplit('/', 1)[1]

    container_repo = repos.get_container_repository()
    container = container_repo.get(container_id)
    if not container:
        raise excep.StoredKeyContainerNotFound(container_id)

    passphrase = None
    private_key = None

    for cs in container.container_secrets:
        secret_repo = repos.get_secret_repository()
        if cs.name == 'private_key':
            private_key = secret_repo.get(cs.secret_id)
        elif cs.name == 'private_key_passphrase':
            passphrase = secret_repo.get(cs.secret_id)

    if not private_key:
        raise excep.StoredKeyPrivateKeyNotFound(container_id)

    pkey = crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        private_key,
        passphrase)

    subject_name = order_model.meta.get('subject_name')
    subject_name_dns = ldap.dn.str2dn(subject_name)
    extensions = order_model.meta.get('extensions', None)

    req = crypto.X509Req()
    subj = req.get_subject()
    for ava in subject_name_dns:
        for key, val, extra in ava:
            setattr(subj, key.upper(), val)
    req.set_pubkey(pkey)
    if extensions:
        # TODO(alee-3) We need code here to parse the encoded extensions and
        # convert them into X509Extension objects.  This code will also be
        # used in the validation code.  Commenting out for now till we figure
        # out how to do this.
        # req.add_extensions(extensions)
        pass
    req.sign(pkey, 'sha256')

    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    return csr


def _notify_ca_unavailable(order_model, result):
    """Notify observer(s) that the CA was unavailable at this time."""
    cert.EVENT_PLUGIN_MANAGER.notify_ca_is_unavailable(
        order_model.project_id,
        hrefs.convert_order_to_href(order_model.id),
        result.status_message,
        result.retry_msec)


def _save_plugin_metadata(order_model, plugin_meta):
    """Add plugin metadata to an order."""

    if not isinstance(plugin_meta, dict):
        plugin_meta = {}

    order_plugin_meta_repo = repos.get_order_plugin_meta_repository()
    order_plugin_meta_repo.save(plugin_meta, order_model)


def _save_secrets(result, project_model):
    cert_secret_model, transport_key_model = plugin.store_secret(
        unencrypted_raw=result.certificate,
        content_type_raw='application/pkix-cert',
        content_encoding='base64',
        spec={},
        secret_model=None,
        project_model=project_model)

    # save the certificate chain as a secret.
    if result.intermediates:
        intermediates_secret_model, transport_key_model = plugin.store_secret(
            unencrypted_raw=result.intermediates,
            content_type_raw='application/pkix-cert',
            content_encoding='base64',
            spec={},
            secret_model=None,
            project_model=project_model
        )
    else:
        intermediates_secret_model = None

    container_model = models.Container()
    container_model.type = "certificate"
    container_model.status = models.States.ACTIVE
    container_model.project_id = project_model.id
    container_repo = repos.get_container_repository()
    container_repo.create_from(container_model)

    # create container_secret for certificate
    new_consec_assoc = models.ContainerSecret()
    new_consec_assoc.name = 'certificate'
    new_consec_assoc.container_id = container_model.id
    new_consec_assoc.secret_id = cert_secret_model.id
    container_secret_repo = repos.get_container_secret_repository()
    container_secret_repo.create_from(new_consec_assoc)

    if intermediates_secret_model:
        # create container_secret for intermediate certs
        new_consec_assoc = models.ContainerSecret()
        new_consec_assoc.name = 'intermediates'
        new_consec_assoc.container_id = container_model.id
        new_consec_assoc.secret_id = intermediates_secret_model.id
        container_secret_repo.create_from(new_consec_assoc)

    return container_model
