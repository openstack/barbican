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

from ldap3.utils.dn import parse_dn
from OpenSSL import crypto

from barbican.common import exception as excep
from barbican.common import hrefs
from barbican.common import resources as res
import barbican.common.utils as utils
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin.interface import certificate_manager as cert
from barbican.plugin import resources as plugin
from barbican.tasks import common

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


def refresh_certificate_resources():
    # Before CA operations can be performed, the CA table must be populated
    cert.CertificatePluginManager().refresh_ca_table()


def issue_certificate_request(order_model, project_model, result_follow_on):
    """Create the initial order with CA.

    Note that this method may be called more than once if retries are
    required. Barbican metadata is used to store intermediate information,
    including selected plugins by name, to support such retries.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :param: result_follow_on - A :class:`FollowOnProcessingStatusDTO` instance
        instantiated by the client that this function may optionally update
        with information on how to process this task into the future.
    :returns: container_model - container with the relevant cert if
        the request has been completed.  None otherwise
    """
    plugin_meta = _get_plugin_meta(order_model)
    barbican_meta = _get_barbican_meta(order_model)

    # TODO(john-wood-w) We need to de-conflict barbican_meta (stored with order
    # and not shown to plugins) with barbican_meta_dto (shared with plugins).
    # As a minimum we should change the name of the DTO to something like
    # 'extended_meta_dto' or some such.
    barbican_meta_for_plugins_dto = cert.BarbicanMetaDTO()

    # refresh the CA table.  This is mostly a no-op unless the entries
    # for a plugin are expired.
    cert.CertificatePluginManager().refresh_ca_table()

    cert_plugin = _get_cert_plugin(barbican_meta,
                                   barbican_meta_for_plugins_dto,
                                   order_model, project_model)
    barbican_meta['plugin_name'] = utils.generate_fullname_for(cert_plugin)

    # Generate CSR if needed.
    request_type = order_model.meta.get(cert.REQUEST_TYPE)
    if request_type == cert.CertificateRequestType.STORED_KEY_REQUEST:
        csr = barbican_meta.get('generated_csr')
        if csr is None:
            # TODO(alee) Fix this to be a non-project specific call once
            # the ACL patches go in.
            csr = _generate_csr_from_private_key(order_model, project_model)
            barbican_meta['generated_csr'] = csr
        barbican_meta_for_plugins_dto.generated_csr = csr

    result = cert_plugin.issue_certificate_request(
        order_model.id, order_model.meta,
        plugin_meta, barbican_meta_for_plugins_dto)

    # Save plugin and barbican metadata for this order.
    _save_plugin_metadata(order_model, plugin_meta)
    _save_barbican_metadata(order_model, barbican_meta)

    # Handle result
    return _handle_task_result(
        result, result_follow_on, order_model, project_model, request_type,
        unavailable_status=ORDER_STATUS_CA_UNAVAIL_FOR_ISSUE)


def _get_cert_plugin(barbican_meta, barbican_meta_for_plugins_dto,
                     order_model, project_model):
    cert_plugin_name = barbican_meta.get('plugin_name')
    if cert_plugin_name:
        return cert.CertificatePluginManager().get_plugin_by_name(
            cert_plugin_name)
    ca_id = _get_ca_id(order_model.meta, project_model.id)
    if ca_id:
        ca = repos.get_ca_repository().get(ca_id)
        barbican_meta_for_plugins_dto.plugin_ca_id = ca.plugin_ca_id
        return cert.CertificatePluginManager().get_plugin_by_name(
            ca.plugin_name)
    else:
        return cert.CertificatePluginManager().get_plugin(order_model.meta)


def check_certificate_request(order_model, project_model, result_follow_on):
    """Check the status of a certificate request with the CA.

    Note that this method may be called more than once if retries are
    required. Barbican metadata is used to store intermediate information,
    including selected plugins by name, to support such retries.

    :param: order_model - order associated with this cert request
    :param: project_model - project associated with this request
    :param: result_follow_on - A :class:`FollowOnProcessingStatusDTO` instance
        instantiated by the client that this function may optionally update
        with information on how to process this task into the future.
    :returns: container_model - container with the relevant cert if the
        request has been completed.  None otherwise.
    """
    plugin_meta = _get_plugin_meta(order_model)
    barbican_meta = _get_barbican_meta(order_model)

    # TODO(john-wood-w) See note above about DTO's name.
    barbican_meta_for_plugins_dto = cert.BarbicanMetaDTO()

    cert_plugin = cert.CertificatePluginManager().get_plugin_by_name(
        barbican_meta.get('plugin_name'))

    result = cert_plugin.check_certificate_status(
        order_model.id, order_model.meta,
        plugin_meta, barbican_meta_for_plugins_dto)

    # Save plugin order plugin state
    _save_plugin_metadata(order_model, plugin_meta)

    request_type = order_model.meta.get(cert.REQUEST_TYPE)
    return _handle_task_result(
        result, result_follow_on, order_model, project_model, request_type,
        unavailable_status=ORDER_STATUS_CA_UNAVAIL_FOR_CHECK)


def create_subordinate_ca(project_model, name, description, subject_dn,
                          parent_ca_ref, creator_id):
    """Create a subordinate CA

    :param name - name of the subordinate CA
    :param: description - description of the subordinate CA
    :param: subject_dn - subject DN of the subordinate CA
    :param: parent_ca_ref - Barbican URL reference to the parent CA
    :param: creator_id - id for creator of the subordinate CA
    :return: :class models.CertificateAuthority model object for new sub CA
    """
    # check that the parent ref exists and is accessible
    parent_ca_id = hrefs.get_ca_id_from_ref(parent_ca_ref)
    ca_repo = repos.get_ca_repository()
    parent_ca = ca_repo.get(entity_id=parent_ca_id, suppress_exception=True)
    if not parent_ca:
        raise excep.InvalidParentCA(parent_ca_ref=parent_ca_ref)

    # Parent CA must be a base CA or a subCA owned by this project
    if (parent_ca.project_id is not None and
            parent_ca.project_id != project_model.id):
        raise excep.UnauthorizedSubCA()

    # get the parent plugin, raises CertPluginNotFound if missing
    cert_plugin = cert.CertificatePluginManager().get_plugin_by_name(
        parent_ca.plugin_name)

    # confirm that the plugin supports creating subordinate CAs
    if not cert_plugin.supports_create_ca():
        raise excep.SubCAsNotSupported()

    # make call to create the subordinate ca
    create_ca_dto = cert.CACreateDTO(
        name=name,
        description=description,
        subject_dn=subject_dn,
        parent_ca_id=parent_ca.plugin_ca_id)

    new_ca_dict = cert_plugin.create_ca(create_ca_dto)
    if not new_ca_dict:
        raise excep.SubCANotCreated(name=name)

    # create and store the subordinate CA as a new certificate authority object
    new_ca_dict['plugin_name'] = parent_ca.plugin_name
    new_ca_dict['creator_id'] = creator_id
    new_ca_dict['project_id'] = project_model.id
    new_ca = models.CertificateAuthority(new_ca_dict)
    ca_repo.create_from(new_ca)

    return new_ca


def delete_subordinate_ca(external_project_id, ca):
    """Deletes a subordinate CA and any related artifacts

    :param external_project_id: external project ID
    :param ca: class:`models.CertificateAuthority` to be deleted
    :return: None
     """
    # TODO(alee) See if the checks below can be moved to the RBAC code

    # Check that this CA is a subCA
    if ca.project_id is None:
        raise excep.CannotDeleteBaseCA()

    # Check that the user's project owns this subCA
    project = res.get_or_create_project(external_project_id)
    if ca.project_id != project.id:
        raise excep.UnauthorizedSubCA()

    project_ca_repo = repos.get_project_ca_repository()
    (project_cas, _, _, _) = project_ca_repo.get_by_create_date(
        project_id=project.id, ca_id=ca.id,
        suppress_exception=True)

    preferred_ca_repo = repos.get_preferred_ca_repository()
    (preferred_cas, _, _, _) = preferred_ca_repo.get_by_create_date(
        project_id=project.id, ca_id=ca.id, suppress_exception=True)

    # Can not delete a project preferred CA, if other project CAs exist. One
    # of those needs to be designated as the preferred CA first.
    if project_cas and preferred_cas and not is_last_project_ca(project.id):
        raise excep.CannotDeletePreferredCA()

    # Remove the CA as preferred
    if preferred_cas:
        preferred_ca_repo.delete_entity_by_id(preferred_cas[0].id,
                                              external_project_id)
    # Remove the CA from project list
    if project_cas:
        project_ca_repo.delete_entity_by_id(project_cas[0].id,
                                            external_project_id)

    # Delete the CA entry from plugin
    cert_plugin = cert.CertificatePluginManager().get_plugin_by_name(
        ca.plugin_name)
    cert_plugin.delete_ca(ca.plugin_ca_id)

    # Finally, delete the CA entity from the CA repository
    ca_repo = repos.get_ca_repository()
    ca_repo.delete_entity_by_id(
        entity_id=ca.id,
        external_project_id=external_project_id)


def is_last_project_ca(project_id):
    """Returns True iff project has exactly one project CA

    :param project_id: internal project ID
    :return: Boolean
     """
    project_ca_repo = repos.get_project_ca_repository()
    _, _, _, total = project_ca_repo.get_by_create_date(
        project_id=project_id,
        suppress_exception=True
    )
    return total == 1


def _handle_task_result(result, result_follow_on, order_model,
                        project_model, request_type, unavailable_status):
    if cert.CertificateStatus.WAITING_FOR_CA == result.status:
        _update_result_follow_on(
            result_follow_on,
            order_status=ORDER_STATUS_REQUEST_PENDING,
            retry_task=common.RetryTasks.INVOKE_CERT_STATUS_CHECK_TASK,
            retry_msec=result.retry_msec)
    elif cert.CertificateStatus.CERTIFICATE_GENERATED == result.status:
        _update_result_follow_on(
            result_follow_on,
            order_status=ORDER_STATUS_CERT_GENERATED)
        container_model = _save_secrets(result, project_model, request_type,
                                        order_model)
        return container_model
    elif cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN == result.status:
        raise cert.CertificateStatusClientDataIssue(result.status_message)
    elif cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST == result.status:
        _update_result_follow_on(
            result_follow_on,
            order_status=unavailable_status,
            retry_task=common.RetryTasks.INVOKE_SAME_TASK,
            retry_msec=cert.ERROR_RETRY_MSEC)
        _notify_ca_unavailable(order_model, result)
    elif cert.CertificateStatus.INVALID_OPERATION == result.status:
        raise cert.CertificateStatusInvalidOperation(result.status_message)
    else:
        raise cert.CertificateStatusNotSupported(result.status)

    return None


def _add_private_key_to_generated_cert_container(container_id, order_model,
                                                 project_model):
    keypair_container_id, keypair_container = _get_container_from_order_meta(
        order_model, project_model)
    private_key_id = None

    for cs in keypair_container.container_secrets:
        if cs.name == 'private_key':
            private_key_id = cs.secret_id

    new_consec_assoc = models.ContainerSecret()
    new_consec_assoc.name = 'private_key'
    new_consec_assoc.container_id = container_id
    new_consec_assoc.secret_id = private_key_id
    container_secret_repo = repos.get_container_secret_repository()
    container_secret_repo.create_from(new_consec_assoc)


def modify_certificate_request(order_model, updated_meta):
    """Update the order with CA."""
    # TODO(chellygel): Add the modify certificate request logic.
    LOG.debug('in modify_certificate_request')
    raise NotImplementedError  # pragma: no cover


def get_global_preferred_ca():
    project = res.get_or_create_global_preferred_project()
    preferred_ca_repository = repos.get_preferred_ca_repository()
    cas = preferred_ca_repository.get_project_entities(project.id)
    if not cas:
        return None
    else:
        return cas[0]


def get_project_preferred_ca_id(project_id):
    """Compute the preferred CA ID for a project

    First priority: a preferred CA is defined for the project
    Second priority: a preferred CA is defined globally
    Else: None
    """
    preferred_ca_repository = repos.get_preferred_ca_repository()
    cas, offset, limit, total = preferred_ca_repository.get_by_create_date(
        project_id=project_id, suppress_exception=True)
    if total > 0:
        return cas[0].ca_id
    global_ca = get_global_preferred_ca()
    if global_ca:
        return global_ca.ca_id


def _get_ca_id(order_meta, project_id):
    ca_id = order_meta.get(cert.CA_ID)
    if ca_id:
        return ca_id

    return get_project_preferred_ca_id(project_id)


def _update_result_follow_on(
        result_follow_on,
        order_status=None,
        retry_task=common.RetryTasks.NO_ACTION_REQUIRED,
        retry_msec=common.RETRY_MSEC_DEFAULT):
    if order_status:
        result_follow_on.status = order_status.id
        result_follow_on.status_message = order_status.message
    result_follow_on.retry_task = retry_task
    if retry_msec and retry_msec >= 0:
        result_follow_on.retry_msec = retry_msec


def _get_plugin_meta(order_model):
    if order_model:
        order_plugin_meta_repo = repos.get_order_plugin_meta_repository()
        return order_plugin_meta_repo.get_metadata_for_order(order_model.id)
    else:
        return {}


def _get_barbican_meta(order_model):
    if order_model:
        order_barbican_meta_repo = repos.get_order_barbican_meta_repository()
        return order_barbican_meta_repo.get_metadata_for_order(order_model.id)
    else:
        return {}


def _generate_csr_from_private_key(order_model, project_model):
    """Generate a CSR from the private key.

    :param: order_model - order for the request
    :param: project_model - project for this request
    :return: CSR (certificate signing request) in PEM format
    :raise: :class:`StoredKeyPrivateKeyNotFound` if private key not found
            :class:`StoredKeyContainerNotFound` if container not found
    """
    container_id, container = _get_container_from_order_meta(order_model,
                                                             project_model)

    if not container:
        raise excep.StoredKeyContainerNotFound(container_id)

    passphrase = None
    private_key = None

    for cs in container.container_secrets:
        secret_repo = repos.get_secret_repository()
        if cs.name == 'private_key':
            private_key_model = secret_repo.get(
                cs.secret_id,
                project_model.external_id)
            private_key = plugin.get_secret(
                'application/pkcs8',
                private_key_model,
                project_model)
        elif cs.name == 'private_key_passphrase':
            passphrase_model = secret_repo.get(
                cs.secret_id,
                project_model.external_id)
            passphrase = plugin.get_secret(
                'text/plain;charset=utf-8',
                passphrase_model,
                project_model)
            passphrase = str(passphrase)

    if not private_key:
        raise excep.StoredKeyPrivateKeyNotFound(container.id)

    if passphrase is None:
        pkey = crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            private_key
        )
    else:
        pkey = crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            private_key,
            passphrase.encode('utf-8')
        )

    subject_name = order_model.meta.get('subject_dn')
    subject_name_dns = parse_dn(subject_name)
    extensions = order_model.meta.get('extensions', None)

    req = crypto.X509Req()
    subj = req.get_subject()

    # Note: must iterate over the DNs in reverse order, or the resulting
    # subject name will be reversed.
    for ava in reversed(subject_name_dns):
        key, val, extra = ava
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


def _get_container_from_order_meta(order_model, project_model):
    container_ref = order_model.meta.get('container_ref')

    # extract container_id as the last part of the URL
    container_id = hrefs.get_container_id_from_ref(container_ref)

    container_repo = repos.get_container_repository()
    container = container_repo.get(container_id,
                                   project_model.external_id,
                                   suppress_exception=True)
    return container_id, container


def _notify_ca_unavailable(order_model, result):
    """Notify observer(s) that the CA was unavailable at this time."""
    cert.get_event_plugin_manager().notify_ca_is_unavailable(
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


def _save_barbican_metadata(order_model, barbican_meta):
    """Add barbican metadata to an order."""

    if not isinstance(barbican_meta, dict):
        barbican_meta = {}

    order_barbican_meta_repo = repos.get_order_barbican_meta_repository()
    order_barbican_meta_repo.save(barbican_meta, order_model)


def _save_secrets(result, project_model, request_type, order_model):
    cert_secret_model, transport_key_model = plugin.store_secret(
        unencrypted_raw=result.certificate,
        content_type_raw='application/octet-stream',
        content_encoding='base64',
        secret_model=models.Secret(),
        project_model=project_model)

    # save the certificate chain as a secret.
    if result.intermediates:
        intermediates_secret_model, transport_key_model = plugin.store_secret(
            unencrypted_raw=result.intermediates,
            content_type_raw='application/octet-stream',
            content_encoding='base64',
            secret_model=models.Secret(),
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

    if request_type == cert.CertificateRequestType.STORED_KEY_REQUEST:
        _add_private_key_to_generated_cert_container(container_model.id,
                                                     order_model,
                                                     project_model)

    return container_model
