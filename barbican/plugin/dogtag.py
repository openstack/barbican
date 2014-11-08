# Copyright (c) 2014 Red Hat, Inc.
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

import os
import uuid

from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from oslo.config import cfg
import pki
import pki.cert
import pki.client
import pki.crypto as cryptoutil
import pki.key as key
import pki.kra
import pki.profile
from requests import exceptions as request_exceptions

from barbican.common import exception
from barbican.common import utils
from barbican.openstack.common import gettextutils as u
import barbican.plugin.interface.certificate_manager as cm
import barbican.plugin.interface.secret_store as sstore

CONF = cfg.CONF
LOG = utils.getLogger(__name__)

dogtag_plugin_group = cfg.OptGroup(name='dogtag_plugin',
                                   title="Dogtag Plugin Options")
dogtag_plugin_opts = [
    cfg.StrOpt('pem_path',
               help=u._('Path to PEM file for authentication')),
    cfg.StrOpt('dogtag_host',
               default="localhost",
               help=u._('Hostname for the Dogtag instance')),
    cfg.StrOpt('dogtag_port',
               default="8443",
               help=u._('Port for the Dogtag instance')),
    cfg.StrOpt('nss_db_path',
               help=u._('Path to the NSS certificate database')),
    cfg.StrOpt('nss_password',
               help=u._('Password for NSS certificate database'))
]

CONF.register_group(dogtag_plugin_group)
CONF.register_opts(dogtag_plugin_opts, group=dogtag_plugin_group)


def setup_nss_db(conf):
    crypto = None
    create_nss_db = False
    nss_db_path = conf.dogtag_plugin.nss_db_path
    if nss_db_path is not None:
        nss_password = conf.dogtag_plugin.nss_password
        if nss_password is None:
            raise ValueError(u._("nss_password is required"))

        if not os.path.exists(nss_db_path):
            create_nss_db = True
            cryptoutil.NSSCryptoProvider.setup_database(
                nss_db_path, nss_password, over_write=True)

        crypto = cryptoutil.NSSCryptoProvider(nss_db_path, nss_password)

    return crypto, create_nss_db


def create_connection(conf, subsystem_path):
    pem_path = conf.dogtag_plugin.pem_path
    if pem_path is None:
        raise ValueError(u._("pem_path is required"))
    connection = pki.client.PKIConnection(
        'https',
        conf.dogtag_plugin.dogtag_host,
        conf.dogtag_plugin.dogtag_port,
        subsystem_path)
    connection.set_authentication_cert(pem_path)
    return connection


class DogtagPluginAlgorithmException(exception.BarbicanException):
    message = u._("Invalid algorithm passed in")


class DogtagPluginNotSupportedException(exception.NotSupported):
    message = u._("Operation not supported by Dogtag Plugin")

    def __init__(self, msg=None):
        if not msg:
            message = self.message
        else:
            message = msg

        super(DogtagPluginNotSupportedException, self).__init__(message)


class DogtagKRAPlugin(sstore.SecretStoreBase):
    """Implementation of the secret store plugin with KRA as the backend."""

    TRANSPORT_NICK = "KRA transport cert"

    # metadata constants
    ALG = "alg"
    BIT_LENGTH = "bit_length"
    KEY_ID = "key_id"
    SECRET_TYPE = "secret_type"
    SECRET_MODE = "secret_mode"
    PASSPHRASE_KEY_ID = "passphrase_key_id"
    CONVERT_TO_PEM = "convert_to_pem"

    # string constants
    DSA_PRIVATE_KEY_HEADER = '-----BEGIN DSA PRIVATE KEY-----'
    DSA_PRIVATE_KEY_FOOTER = '-----END DSA PRIVATE KEY-----'
    DSA_PUBLIC_KEY_HEADER = '-----BEGIN DSA PUBLIC KEY-----'
    DSA_PUBLIC_KEY_FOOTER = '-----END DSA PUBLIC KEY-----'

    def __init__(self, conf=CONF):
        """Constructor - create the keyclient."""
        LOG.debug("starting DogtagKRAPlugin init")
        crypto, create_nss_db = setup_nss_db(conf)
        connection = create_connection(conf, 'kra')

        # create kraclient
        kraclient = pki.kra.KRAClient(connection, crypto)
        self.keyclient = kraclient.keys
        self.systemcert_client = kraclient.system_certs

        if crypto is not None:
            if create_nss_db:
                self.import_transport_cert(crypto)

            crypto.initialize()
            self.keyclient.set_transport_cert(
                DogtagKRAPlugin.TRANSPORT_NICK)

        LOG.debug("completed DogtagKRAPlugin init")

    def import_transport_cert(self, crypto):
        # Get transport cert and insert in the certdb
        transport_cert = self.systemcert_client.get_transport_cert()
        crypto.import_cert(DogtagKRAPlugin.TRANSPORT_NICK,
                           transport_cert,
                           "u,u,u")

    def store_secret(self, secret_dto):
        """Store a secret in the KRA

        If secret_dto.transport_key is not None, then we expect
        secret_dto.secret to include a base64 encoded PKIArchiveOptions
        structure as defined in section 6.4 of RFC 2511. This package contains
        a transport key wrapped session key, the session key wrapped secret
        and parameters to specify the symmetric key wrapping.

        Otherwise, the data is unencrypted and we use a call to archive_key()
        to have the Dogtag KRA client generate the relevant session keys.

        The secret_dto contains additional information on the type of secret
        that is being stored.  We will use that shortly.  For, now, lets just
        assume that its all PASS_PHRASE_TYPE

        Returns a dict with the relevant metadata (which in this case is just
        the key_id
        """
        data_type = key.KeyClient.PASS_PHRASE_TYPE
        client_key_id = uuid.uuid4().hex
        if secret_dto.transport_key is not None:
            # TODO(alee-3) send the transport key with the archival request
            # once the Dogtag Client API changes.
            response = self.keyclient.archive_pki_options(
                client_key_id,
                data_type,
                secret_dto.secret,
                key_algorithm=None,
                key_size=None)
        else:
            response = self.keyclient.archive_key(
                client_key_id,
                data_type,
                secret_dto.secret,
                key_algorithm=None,
                key_size=None)

        meta_dict = {DogtagKRAPlugin.KEY_ID: response.get_key_id()}

        self._store_secret_attributes(meta_dict, secret_dto)
        return meta_dict

    def get_secret(self, secret_metadata):
        """Retrieve a secret from the KRA

        The secret_metadata is simply the dict returned by a store_secret() or
        get_secret() call.  We will extract the key_id from this dict.

        Note: There are two ways to retrieve secrets from the KRA.

        The first method calls retrieve_key without a wrapping key.  This
        relies on the KRA client to generate a wrapping key (and wrap it with
        the KRA transport cert), and is completely transparent to the
        Barbican server.  What is returned to the caller is the
        unencrypted secret.

        The second way is to provide a wrapping key that would be generated
        on the barbican client.  That way only the client will be
        able to unwrap the secret.  This wrapping key is provided in the
        secret_metadata by Barbican core.

        Format/Type of the secret returned in the SecretDTO object.
        -----------------------------------------------------------
        The type of the secret returned is always dependent on the way it is
        stored using the store_secret method.

        In case of strings - like passphrase/PEM strings, the return will be a
        string.

        In case of binary data - the return will be the actual binary data.

        In case of retrieving an asymmetric key that is generated using the
        dogtag plugin, then the binary representation of, the asymmetric key in
        PEM format, is returned
        """
        key_id = secret_metadata[DogtagKRAPlugin.KEY_ID]
        secret_type = secret_metadata.get(DogtagKRAPlugin.SECRET_TYPE, None)

        key_spec = sstore.KeySpec(
            alg=secret_metadata.get(DogtagKRAPlugin.ALG, None),
            bit_length=secret_metadata.get(DogtagKRAPlugin.BIT_LENGTH, None),
            mode=secret_metadata.get(DogtagKRAPlugin.SECRET_MODE, None),
            passphrase=None
        )

        passphrase = self._get_passphrase_for_a_private_key(
            secret_metadata, key_spec)

        recovered_key = None
        twsk = DogtagKRAPlugin._get_trans_wrapped_session_key(secret_metadata)

        if DogtagKRAPlugin.CONVERT_TO_PEM in secret_metadata:
            # Case for returning the asymmetric keys generated in KRA.
            # Asymmetric keys generated in KRA are not generated in PEM format.
            # This marker DogtagKRAPlugin.CONVERT_TO_PEM is set in the
            # secret_metadata for asymmetric keys generated in KRA to
            # help convert the returned private/public keys to PEM format and
            # eventually return the binary data of the keys in PEM format.

            if secret_type == sstore.SecretType.PUBLIC:
                # Public key should be retrieved using the get_key_info method
                # as it is treated as an attribute of the asymmetric key pair
                # stored in the KRA database.

                if key_spec.alg is None:
                    raise sstore.SecretAlgorithmNotSupportedException('None')

                key_info = self.keyclient.get_key_info(key_id)
                if key_spec.alg.upper() == key.KeyClient.RSA_ALGORITHM:
                    recovered_key = (RSA.importKey(key_info.public_key)
                                     .publickey()
                                     .exportKey('PEM')).encode('utf-8')
                elif key_spec.alg.upper() == key.KeyClient.DSA_ALGORITHM:
                    pub_seq = asn1.DerSequence()
                    pub_seq[:] = key_info.public_key
                    recovered_key = (
                        ("%s\n%s%s" %
                         (DogtagKRAPlugin.DSA_PUBLIC_KEY_HEADER,
                          pub_seq.encode().encode("base64"),
                          DogtagKRAPlugin.DSA_PUBLIC_KEY_FOOTER)
                         ).encode('utf-8')
                    )
                else:
                    raise sstore.SecretAlgorithmNotSupportedException(
                        key_spec.alg.upper()
                    )

            elif secret_type == sstore.SecretType.PRIVATE:
                key_data = self.keyclient.retrieve_key(key_id)
                if key_spec.alg.upper() == key.KeyClient.RSA_ALGORITHM:
                    recovered_key = (
                        (RSA.importKey(key_data.data)
                         .exportKey('PEM', passphrase))
                        .encode('utf-8')
                    )
                elif key_spec.alg.upper() == key.KeyClient.DSA_ALGORITHM:
                    pub_seq = asn1.DerSequence()
                    pub_seq[:] = key_data.data
                    recovered_key = (
                        ("%s\n%s%s" %
                         (DogtagKRAPlugin.DSA_PRIVATE_KEY_HEADER,
                          pub_seq.encode().encode("base64"),
                          DogtagKRAPlugin.DSA_PRIVATE_KEY_FOOTER)
                         ).encode('utf-8')
                    )
                else:
                    raise sstore.SecretAlgorithmNotSupportedException(
                        key_spec.alg.upper()
                    )
        else:
            # TODO(alee-3) send transport key as well when dogtag client API
            # changes in case the transport key has changed.
            key_data = self.keyclient.retrieve_key(key_id, twsk)
            if twsk:
                # The data returned is a byte array.
                recovered_key = key_data.encrypted_data
            else:
                recovered_key = key_data.data

        # TODO(alee) remove final field when content_type is removed
        # from secret_dto
        ret = sstore.SecretDTO(
            type=secret_type,
            secret=recovered_key,
            key_spec=key_spec,
            content_type=None,
            transport_key=None)

        return ret

    def delete_secret(self, secret_metadata):
        """Delete a secret from the KRA

        There is currently no way to delete a secret in Dogtag.
        We will be implementing such a method shortly.
        """
        pass

    def generate_symmetric_key(self, key_spec):
        """Generate a symmetric key

        This calls generate_symmetric_key() on the KRA passing in the
        algorithm, bit_length and id (used as the client_key_id) from
        the secret.  The remaining parameters are not used.

        Returns a metadata object that can be used for retrieving the secret.
        """

        usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE,
                  key.SymKeyGenerationRequest.ENCRYPT_USAGE]

        client_key_id = uuid.uuid4().hex
        algorithm = self._map_algorithm(key_spec.alg.lower())

        if algorithm is None:
            raise DogtagPluginAlgorithmException
        passphrase = key_spec.passphrase
        if passphrase:
            raise DogtagPluginNotSupportedException(
                "Passphrase encryption is not supported for symmetric"
                " key generating algorithms.")

        response = self.keyclient.generate_symmetric_key(
            client_key_id,
            algorithm,
            key_spec.bit_length,
            usages)
        return {DogtagKRAPlugin.ALG: key_spec.alg,
                DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
                DogtagKRAPlugin.SECRET_MODE: key_spec.mode,
                DogtagKRAPlugin.SECRET_TYPE: sstore.SecretType.SYMMETRIC,
                DogtagKRAPlugin.KEY_ID: response.get_key_id()}

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key."""

        usages = [key.AsymKeyGenerationRequest.DECRYPT_USAGE,
                  key.AsymKeyGenerationRequest.ENCRYPT_USAGE]

        client_key_id = uuid.uuid4().hex
        algorithm = self._map_algorithm(key_spec.alg.lower())
        passphrase = key_spec.passphrase

        if algorithm is None:
            raise DogtagPluginAlgorithmException

        passphrase_key_id = None
        passphrase_metadata = None
        if passphrase:
            if algorithm == key.KeyClient.DSA_ALGORITHM:
                raise DogtagPluginNotSupportedException("Passphrase encryption"
                                                        " is not supported for"
                                                        " DSA algorithm")

            stored_passphrase_info = self.keyclient.archive_key(
                uuid.uuid4().hex,
                self.keyclient.PASS_PHRASE_TYPE,
                passphrase)

            passphrase_key_id = stored_passphrase_info.get_key_id()
            passphrase_metadata = {
                DogtagKRAPlugin.KEY_ID: passphrase_key_id
            }

        response = self.keyclient.generate_asymmetric_key(
            client_key_id,
            algorithm,
            key_spec.bit_length,
            usages)

        public_key_metadata = {
            DogtagKRAPlugin.ALG: key_spec.alg,
            DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
            DogtagKRAPlugin.SECRET_TYPE: sstore.SecretType.PUBLIC,
            DogtagKRAPlugin.KEY_ID: response.get_key_id(),
            DogtagKRAPlugin.CONVERT_TO_PEM: "true"
        }

        private_key_metadata = {
            DogtagKRAPlugin.ALG: key_spec.alg,
            DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
            DogtagKRAPlugin.SECRET_TYPE: sstore.SecretType.PRIVATE,
            DogtagKRAPlugin.KEY_ID: response.get_key_id(),
            DogtagKRAPlugin.CONVERT_TO_PEM: "true"
        }

        if passphrase_key_id:
            private_key_metadata[DogtagKRAPlugin.PASSPHRASE_KEY_ID] = (
                passphrase_key_id
            )

        return sstore.AsymmetricKeyMetadataDTO(private_key_metadata,
                                               public_key_metadata,
                                               passphrase_metadata)

    def generate_supports(self, key_spec):
        """Key generation supported?

        Specifies whether the plugin supports key generation with the
        given key_spec.

        For now, we will just check the algorithm.  When dogtag adds a
        call to check the bit length as well, we will use that call to
        take advantage of the bit_length information
        """
        return self._map_algorithm(key_spec.alg) is not None

    def store_secret_supports(self, key_spec):
        """Key storage supported?

        Specifies whether the plugin supports storage of the secret given
        the attributes included in the KeySpec
        """
        return True

    @staticmethod
    def _map_algorithm(algorithm):
        """Map Barbican algorithms to Dogtag plugin algorithms.

        Note that only algorithms supported by Dogtag will be mapped.
        """
        if algorithm == sstore.KeyAlgorithm.AES:
            return key.KeyClient.AES_ALGORITHM
        elif algorithm == sstore.KeyAlgorithm.DES:
            return key.KeyClient.DES_ALGORITHM
        elif algorithm == sstore.KeyAlgorithm.DESEDE:
            return key.KeyClient.DES3_ALGORITHM
        elif algorithm == sstore.KeyAlgorithm.DSA:
            return key.KeyClient.DSA_ALGORITHM
        elif algorithm == sstore.KeyAlgorithm.RSA:
            return key.KeyClient.RSA_ALGORITHM
        elif algorithm == sstore.KeyAlgorithm.DIFFIE_HELLMAN:
            # may be supported, needs to be tested
            return None
        elif algorithm == sstore.KeyAlgorithm.EC:
            # asymmetric keys not yet supported
            return None
        else:
            return None

    @staticmethod
    def _store_secret_attributes(meta_dict, secret_dto):
        # store the following attributes for retrieval
        key_spec = secret_dto.key_spec
        if key_spec is not None:
            if key_spec.alg is not None:
                meta_dict[DogtagKRAPlugin.ALG] = key_spec.alg
            if key_spec.bit_length is not None:
                meta_dict[DogtagKRAPlugin.BIT_LENGTH] = key_spec.bit_length
            if key_spec.mode is not None:
                meta_dict[DogtagKRAPlugin.SECRET_MODE] = key_spec.mode
        if secret_dto.type is not None:
            meta_dict[DogtagKRAPlugin.SECRET_TYPE] = secret_dto.type

    def _get_passphrase_for_a_private_key(self, secret_metadata, key_spec):
        """Retrieve the passphrase for the private key stored in the KRA."""
        secret_type = secret_metadata.get(DogtagKRAPlugin.SECRET_TYPE, None)
        if secret_type is None:
            return None
        if key_spec.alg is None:
            return None

        passphrase = None
        if DogtagKRAPlugin.PASSPHRASE_KEY_ID in secret_metadata:
            if key_spec.alg.upper() == key.KeyClient.RSA_ALGORITHM:
                passphrase = self.keyclient.retrieve_key(
                    secret_metadata.get(DogtagKRAPlugin.PASSPHRASE_KEY_ID)
                ).data
            else:
                if key_spec.alg.upper() == key.KeyClient.DSA_ALGORITHM:
                    raise sstore.SecretGeneralException(
                        "DSA keys should not have a passphrase in the"
                        " database, for being used during retrieval."
                    )
                raise sstore.SecretGeneralException(
                    "Secrets of type " + secret_type +
                    " should not have a passphrase in the database, "
                    "for being used during retrieval."
                )
        return passphrase

    @staticmethod
    def _get_trans_wrapped_session_key(secret_metadata):
        twsk = secret_metadata.get('trans_wrapped_session_key', None)
        secret_type = secret_metadata.get(DogtagKRAPlugin.SECRET_TYPE, None)
        if secret_type in [sstore.SecretType.PUBLIC,
                           sstore.SecretType.PRIVATE]:
            if twsk:
                raise DogtagPluginNotSupportedException(
                    "Encryption using session key is not supported when "
                    "retrieving a " + secret_type + " key.")

        return twsk


def _catch_request_exception(ca_related_function):
    def _catch_ca_unavailable(self, *args, **kwargs):
        try:
            return ca_related_function(self, *args, **kwargs)
        except request_exceptions.RequestException:
            return cm.ResultDTO(
                cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)

    return _catch_ca_unavailable


class DogtagCAPlugin(cm.CertificatePluginBase):
    """Implementation of the cert plugin with Dogtag CA as the backend."""

    # order_metadata fields
    PROFILE_ID = "profile_id"

    # plugin_metadata fields
    REQUEST_ID = "request_id"

    def __init__(self, conf=CONF):
        """Constructor - create the cert clients."""
        crypto, create_nss_db = setup_nss_db(conf)
        connection = create_connection(conf, 'ca')
        self.certclient = pki.cert.CertClient(connection)

        if crypto is not None:
            crypto.initialize()

    def _get_request_id(self, order_id, plugin_meta, operation):
        request_id = plugin_meta.get(self.REQUEST_ID, None)
        if not request_id:
            raise cm.CertificateGeneralException(
                "{0} not found for {1} for order_id {2}".format(
                    self.REQUEST_ID, operation, order_id))
        return request_id

    @_catch_request_exception
    def _get_request(self, request_id):
        try:
            return self.certclient.get_request(request_id)
        except pki.RequestNotFoundException:
            return None

    @_catch_request_exception
    def _get_cert(self, cert_id):
        try:
            return self.certclient.get_cert(cert_id)
        except pki.CertNotFoundException:
            return None

    def check_certificate_status(self, order_id, order_meta, plugin_meta):
        """Check the status of a certificate request.

        :param order_id: ID of the order associated with this request
        :param order_meta: order_metadata associated with this order
        :param plugin_meta: data populated by previous calls for this order,
            in particular the request_id
        :return: cm.ResultDTO
        """
        request_id = self._get_request_id(order_id, plugin_meta, "checking")

        request = self._get_request(request_id)
        if not request:
            raise cm.CertificateGeneralException(
                "No request found for request_id {0} for order {1}".format(
                    request_id, order_id))

        request_status = request.request_status

        if request_status == pki.cert.CertRequestStatus.REJECTED:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message=request.error_message)
        elif request_status == pki.cert.CertRequestStatus.CANCELED:
            return cm.ResultDTO(
                cm.CertificateStatus.REQUEST_CANCELED)
        elif request_status == pki.cert.CertRequestStatus.PENDING:
            return cm.ResultDTO(
                cm.CertificateStatus.WAITING_FOR_CA)
        elif request_status == pki.cert.CertRequestStatus.COMPLETE:
            # get the cert
            cert_id = request.cert_id
            if not cert_id:
                raise cm.CertificateGeneralException(
                    "Request {0} reports status_complete, but no cert_id "
                    "has been returned".format(request_id))

            cert = self._get_cert(cert_id)
            if not cert:
                raise cm.CertificateGeneralException(
                    "Certificate not found for cert_id: {0}".format(cert_id))
            return cm.ResultDTO(
                cm.CertificateStatus.CERTIFICATE_GENERATED,
                certificate=cert.encoded,
                intermediates=cert.pkcs7_cert_chain)
        else:
            raise cm.CertificateGeneralException(
                "Invalid request_status returned by CA")

    @_catch_request_exception
    def issue_certificate_request(self, order_id, order_meta, plugin_meta):
        """Issue a certificate request to Dogtag CA

        For now, we assume that we are talking to the Dogtag CA that
        is deployed with the KRA back-end, and we are connected as a
        CA agent.  This means that we can use the agent convenience
        method to automatically approve the certificate request.

        :param order_id: ID of the order associated with this request
        :param order_meta: dict containing all the inputs required for a
            particular profile.  One of these must be the profile_id.
            The exact fields (both optional and mandatory) depend on the
            profile, but they will be exposed to the user in a method to
            expose syntax.  Depending on the profile, only the relevant fields
            will be populated in the request.  All others will be ignored.
        :param plugin_meta: Used to store data for status check.
        :return: cm.ResultDTO
        """
        profile_id = order_meta.get(self.PROFILE_ID, None)
        if not profile_id:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message="No profile_id specified")

        try:
            enrollment_results = self.certclient.enroll_cert(
                profile_id, order_meta)

            # Although it is possible to create multiple certs in an invocation
            # of enroll_cert, Barbican cannot handle this case.  Assume
            # only once cert and request generated for now.
            enrollment_result = enrollment_results[0]

            request = enrollment_result.request
            if not request:
                raise cm.CertificateGeneralException(
                    "No request returned in enrollment_results")

            # store the request_id in the plugin metadata
            plugin_meta[self.REQUEST_ID] = request.request_id

            cert = enrollment_result.cert
            if not cert:
                request_status = request.request_status
                if request_status == pki.cert.CertRequestStatus.REJECTED:
                    return cm.ResultDTO(
                        cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                        status_message=request.error_message)
                elif request_status == pki.cert.CertRequestStatus.CANCELED:
                    return cm.ResultDTO(
                        cm.CertificateStatus.REQUEST_CANCELED)
                elif request_status == pki.cert.CertRequestStatus.PENDING:
                    return cm.ResultDTO(
                        cm.CertificateStatus.WAITING_FOR_CA)
                elif request_status == pki.cert.CertRequestStatus.COMPLETE:
                    raise cm.CertificateGeneralException(
                        "request_id {0} returns COMPLETE but no cert returned"
                        .format(request.request_id))
                else:
                    raise cm.CertificateGeneralException(
                        "Invalid request_status {0} for request_id {1}"
                        .format(request_status, request.request_id))

            return cm.ResultDTO(
                cm.CertificateStatus.CERTIFICATE_GENERATED,
                certificate=cert.encoded,
                intermediates=cert.pkcs7_cert_chain)

        except pki.BadRequestException as e:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message=e.message)
        except pki.PKIException as e:
            raise cm.CertificateGeneralException(
                "Exception thrown by enroll_cert: {0}".format(e.message))

    def modify_certificate_request(self, order_id, order_meta, plugin_meta):
        """Modify a certificate request.

        Once a certificate request is generated, it cannot be modified.
        The only alternative is to cancel the request (if it has not already
        completed) and attempt a fresh enrolment.  That is what will be
        attempted here.
        :param order_id: ID for this order
        :param order_meta: order metadata.  It is assumed that the newly
            modified request data will be present here.
        :param plugin_meta: data stored on behalf of the plugin for further
            operations
        :return: ResultDTO:
        """
        result_dto = self.cancel_certificate_request(
            order_id, order_meta, plugin_meta)

        if result_dto.status == cm.CertificateStatus.REQUEST_CANCELED:
            return self.issue_certificate_request(
                order_id, order_meta, plugin_meta)
        elif result_dto.status == cm.CertificateStatus.INVALID_OPERATION:
            return cm.ResultDTO(
                cm.CertificateStatus.INVALID_OPERATION,
                status_message="Modify request: unable to cancel: {0}"
                .format(result_dto.status_message))
        else:
            # other status (ca_unavailable, client_data_issue)
            # return result from cancel operation
            return result_dto

    @_catch_request_exception
    def cancel_certificate_request(self, order_id, order_meta, plugin_meta):
        """Cancel a certificate request.

        :param order_id: ID for the order associated with this request
        :param order_meta: order metadata fdr this request
        :param plugin_meta: data stored by plugin for further processing.
            In particular, the request_id
        :return: cm.ResultDTO:
        """
        request_id = self._get_request_id(order_id, plugin_meta, "cancelling")

        try:
            review_response = self.certclient.review_request(request_id)
            self.certclient.cancel_request(request_id, review_response)

            return cm.ResultDTO(cm.CertificateStatus.REQUEST_CANCELED)
        except pki.RequestNotFoundException:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message="no request found for this order")
        except pki.ConflictingOperationException as e:
            return cm.ResultDTO(
                cm.CertificateStatus.INVALID_OPERATION,
                status_message=e.message)

    def supports(self, certificate_spec):
        if cm.CA_TYPE in certificate_spec:
            return certificate_spec[cm.CA_TYPE] == cm.CA_PLUGIN_TYPE_DOGTAG

        if cm.CA_PLUGIN_TYPE_SYMANTEC in certificate_spec:
            # TODO(alee-3) Handle case where SKI is provided
            pass

        return True
