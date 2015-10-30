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

import base64
import copy
import datetime
import os
import uuid

from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from oslo_config import cfg
import pki

subcas_available = True
try:
    import pki.authority as authority
    import pki.feature as feature
except ImportError:
    subcas_available = False

import pki.cert
import pki.client
import pki.crypto as cryptoutil
import pki.key as key
import pki.kra
import pki.profile
from requests import exceptions as request_exceptions

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
import barbican.plugin.interface.certificate_manager as cm
import barbican.plugin.interface.secret_store as sstore

CONF = config.new_config()
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
               help=u._('Password for the NSS certificate databases'),
               secret=True),
    cfg.StrOpt('simple_cmc_profile',
               help=u._('Profile for simple CMC requests')),
    cfg.StrOpt('auto_approved_profiles',
               default="caServerCert",
               help=u._('List of automatically approved enrollment profiles')),
    cfg.StrOpt('ca_expiration_time',
               default=cm.CA_INFO_DEFAULT_EXPIRATION_DAYS,
               help=u._('Time in days for CA entries to expire')),
    cfg.StrOpt('plugin_working_dir',
               help=u._('Working directory for Dogtag plugin'))
]

CONF.register_group(dogtag_plugin_group)
CONF.register_opts(dogtag_plugin_opts, group=dogtag_plugin_group)
config.parse_args(CONF)

CERT_HEADER = "-----BEGIN CERTIFICATE-----"
CERT_FOOTER = "-----END CERTIFICATE-----"

KRA_TRANSPORT_NICK = "KRA transport cert"


def _create_nss_db_if_needed(nss_db_path, nss_password):
    """Creates NSS DB if it's not setup already

    :returns: True or False whether the database was created or not.
    """
    if not os.path.exists(nss_db_path):
        cryptoutil.NSSCryptoProvider.setup_database(
            nss_db_path, nss_password, over_write=True)
        return True
    else:
        LOG.info(u._LI("The nss_db_path provided already exists, so the "
                       "database is assumed to be already set up."))
        return False


def _setup_nss_db_services(conf):
    """Sets up NSS Crypto functions

    This sets up the NSSCryptoProvider and the database it needs for it to
    store certificates. If the path specified in the configuration is already
    existent, it will assume that the database is already setup.

    This will also import the transport cert needed by the KRA if the NSS DB
    was created.
    """
    nss_db_path, nss_password = (conf.dogtag_plugin.nss_db_path,
                                 conf.dogtag_plugin.nss_password)
    if nss_db_path is None:
        LOG.warning(u._LW("nss_db_path was not provided so the crypto "
                          "provider functions were not initialized."))
        return None
    if nss_password is None:
        raise ValueError(u._("nss_password is required"))

    nss_db_created = _create_nss_db_if_needed(nss_db_path, nss_password)
    crypto = cryptoutil.NSSCryptoProvider(nss_db_path, nss_password)
    if nss_db_created:
        _import_kra_transport_cert_to_nss_db(conf, crypto)

    return crypto


def _import_kra_transport_cert_to_nss_db(conf, crypto):
    try:
        connection = create_connection(conf, 'kra')
        kraclient = pki.kra.KRAClient(connection, crypto)
        systemcert_client = kraclient.system_certs

        transport_cert = systemcert_client.get_transport_cert()
        crypto.import_cert(KRA_TRANSPORT_NICK, transport_cert, "u,u,u")
    except Exception as e:
        LOG.error("Error in importing transport cert."
                  " KRA may not be enabled: " + str(e))


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

crypto = _setup_nss_db_services(CONF)
crypto.initialize()


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

    # metadata constants
    ALG = "alg"
    BIT_LENGTH = "bit_length"
    GENERATED = "generated"
    KEY_ID = "key_id"
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
        connection = create_connection(conf, 'kra')

        # create kraclient
        kraclient = pki.kra.KRAClient(connection, crypto)
        self.keyclient = kraclient.keys

        self.keyclient.set_transport_cert(KRA_TRANSPORT_NICK)

        LOG.debug("completed DogtagKRAPlugin init")

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

    def get_secret(self, secret_type, secret_metadata):
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

        key_spec = sstore.KeySpec(
            alg=secret_metadata.get(DogtagKRAPlugin.ALG, None),
            bit_length=secret_metadata.get(DogtagKRAPlugin.BIT_LENGTH, None),
            mode=secret_metadata.get(DogtagKRAPlugin.SECRET_MODE, None),
            passphrase=None
        )

        generated = secret_metadata.get(DogtagKRAPlugin.GENERATED, False)

        passphrase = self._get_passphrase_for_a_private_key(
            secret_type, secret_metadata, key_spec)

        recovered_key = None
        twsk = DogtagKRAPlugin._get_trans_wrapped_session_key(secret_type,
                                                              secret_metadata)

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
                         .exportKey('PEM', passphrase, 8))
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

        if generated:
            recovered_key = base64.b64encode(recovered_key)

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
                u._("Passphrase encryption is not supported for symmetric"
                    " key generating algorithms."))

        response = self.keyclient.generate_symmetric_key(
            client_key_id,
            algorithm,
            key_spec.bit_length,
            usages)

        # Barbican expects stored keys to be base 64 encoded.  We need to
        # add flag to the keyclient.generate_symmetric_key() call above
        # to ensure that the key that is stored is base64 encoded.
        #
        # As a workaround until that update is available, we will store a
        # parameter "generated"  to indicate that the response must be base64
        # encoded on retrieval.  Note that this will not work for transport
        # key encoded data.
        return {DogtagKRAPlugin.ALG: key_spec.alg,
                DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
                DogtagKRAPlugin.SECRET_MODE: key_spec.mode,
                DogtagKRAPlugin.KEY_ID: response.get_key_id(),
                DogtagKRAPlugin.GENERATED: True}

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key.

        Note that barbican expects all secrets to be base64 encoded.
        """

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
                raise DogtagPluginNotSupportedException(
                    u._("Passphrase encryption is not "
                        "supported for DSA algorithm")
                )

            stored_passphrase_info = self.keyclient.archive_key(
                uuid.uuid4().hex,
                self.keyclient.PASS_PHRASE_TYPE,
                base64.b64encode(passphrase))

            passphrase_key_id = stored_passphrase_info.get_key_id()
            passphrase_metadata = {
                DogtagKRAPlugin.KEY_ID: passphrase_key_id
            }

        # Barbican expects stored keys to be base 64 encoded.  We need to
        # add flag to the keyclient.generate_asymmetric_key() call above
        # to ensure that the key that is stored is base64 encoded.
        #
        # As a workaround until that update is available, we will store a
        # parameter "generated"  to indicate that the response must be base64
        # encoded on retrieval.  Note that this will not work for transport
        # key encoded data.

        response = self.keyclient.generate_asymmetric_key(
            client_key_id,
            algorithm,
            key_spec.bit_length,
            usages)

        public_key_metadata = {
            DogtagKRAPlugin.ALG: key_spec.alg,
            DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
            DogtagKRAPlugin.KEY_ID: response.get_key_id(),
            DogtagKRAPlugin.CONVERT_TO_PEM: "true",
            DogtagKRAPlugin.GENERATED: True
        }

        private_key_metadata = {
            DogtagKRAPlugin.ALG: key_spec.alg,
            DogtagKRAPlugin.BIT_LENGTH: key_spec.bit_length,
            DogtagKRAPlugin.KEY_ID: response.get_key_id(),
            DogtagKRAPlugin.CONVERT_TO_PEM: "true",
            DogtagKRAPlugin.GENERATED: True
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
        if algorithm is None:
            return None

        if algorithm.lower() == sstore.KeyAlgorithm.AES.lower():
            return key.KeyClient.AES_ALGORITHM
        elif algorithm.lower() == sstore.KeyAlgorithm.DES.lower():
            return key.KeyClient.DES_ALGORITHM
        elif algorithm.lower() == sstore.KeyAlgorithm.DESEDE.lower():
            return key.KeyClient.DES3_ALGORITHM
        elif algorithm.lower() == sstore.KeyAlgorithm.DSA.lower():
            return key.KeyClient.DSA_ALGORITHM
        elif algorithm.lower() == sstore.KeyAlgorithm.RSA.lower():
            return key.KeyClient.RSA_ALGORITHM
        elif algorithm.lower() == sstore.KeyAlgorithm.DIFFIE_HELLMAN.lower():
            # may be supported, needs to be tested
            return None
        elif algorithm.lower() == sstore.KeyAlgorithm.EC.lower():
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

    def _get_passphrase_for_a_private_key(self, secret_type, secret_metadata,
                                          key_spec):
        """Retrieve the passphrase for the private key stored in the KRA."""
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
                        u._("DSA keys should not have a passphrase in the"
                            " database, for being used during retrieval.")
                    )
                raise sstore.SecretGeneralException(
                    u._("Secrets of type {secret_type} should not have a "
                        "passphrase in the database, for being used during "
                        "retrieval.").format(secret_type=secret_type)
                )

        # note that Barbican expects the passphrase to be base64 encoded when
        # stored, so we need to decode it.
        if passphrase:
            passphrase = base64.b64decode(passphrase)
        return passphrase

    @staticmethod
    def _get_trans_wrapped_session_key(secret_type, secret_metadata):
        twsk = secret_metadata.get('trans_wrapped_session_key', None)
        if secret_type in [sstore.SecretType.PUBLIC,
                           sstore.SecretType.PRIVATE]:
            if twsk:
                raise DogtagPluginNotSupportedException(
                    u._("Encryption using session key is not supported when "
                        "retrieving a {secret_type} "
                        "key.").format(secret_type=secret_type)
                )

        return twsk


def _catch_request_exception(ca_related_function):
    def _catch_ca_unavailable(self, *args, **kwargs):
        try:
            return ca_related_function(self, *args, **kwargs)
        except request_exceptions.RequestException:
            return cm.ResultDTO(
                cm.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST)

    return _catch_ca_unavailable


def _catch_enrollment_exceptions(ca_related_function):
    def _catch_enrollment_exception(self, *args, **kwargs):
        try:
            return ca_related_function(self, *args, **kwargs)
        except pki.BadRequestException as e:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message=e.message)
        except pki.PKIException as e:
            raise cm.CertificateGeneralException(
                u._("Exception thrown by enroll_cert: {message}").format(
                    message=e.message))

    return _catch_enrollment_exception


def _catch_subca_creation_exceptions(ca_related_function):
    def _catch_subca_exception(self, *args, **kwargs):
        try:
            return ca_related_function(self, *args, **kwargs)
        except pki.BadRequestException as e:
            raise exception.BadSubCACreationRequest(reason=e.message)
        except pki.PKIException as e:
            raise exception.SubCACreationErrors(reason=e.message)
        except request_exceptions.RequestException:
            raise exception.SubCACreationErrors(
                reason="Unable to connect to CA")

    return _catch_subca_exception


def _catch_subca_deletion_exceptions(ca_related_function):
    def _catch_subca_exception(self, *args, **kwargs):
        try:
            return ca_related_function(self, *args, **kwargs)
        except pki.ResourceNotFoundException as e:
            LOG.warning(u._LI("Sub-CA already deleted"))
            pass
        except pki.PKIException as e:
            raise exception.SubCADeletionErrors(reason=e.message)
        except request_exceptions.RequestException:
            raise exception.SubCACreationErrors(
                reason="Unable to connect to CA")

    return _catch_subca_exception


class DogtagCAPlugin(cm.CertificatePluginBase):
    """Implementation of the cert plugin with Dogtag CA as the backend."""

    # order_metadata fields
    PROFILE_ID = "profile_id"

    # plugin_metadata fields
    REQUEST_ID = "request_id"

    def __init__(self, conf=CONF):
        """Constructor - create the cert clients."""
        connection = create_connection(conf, 'ca')
        self.certclient = pki.cert.CertClient(connection)
        self.simple_cmc_profile = conf.dogtag_plugin.simple_cmc_profile
        self.auto_approved_profiles = conf.dogtag_plugin.auto_approved_profiles

        self.working_dir = conf.dogtag_plugin.plugin_working_dir
        if not os.path.isdir(self.working_dir):
            os.mkdir(self.working_dir)

        self._expiration = None
        self._expiration_delta = conf.dogtag_plugin.ca_expiration_time
        self._expiration_data_path = os.path.join(self.working_dir,
                                                  "expiration_data.txt")

        self._host_aid_path = os.path.join(self.working_dir, "host_aid.txt")
        self._host_aid = None

        if not os.path.isfile(self._expiration_data_path):
            self.expiration = datetime.datetime.utcnow()

        global subcas_available
        subcas_available = self._are_subcas_enabled_on_backend(connection)
        if subcas_available:
            self.authority_client = authority.AuthorityClient(connection)
            if not os.path.isfile(self._host_aid_path):
                self.host_aid = self.get_host_aid()

    @property
    def expiration(self):
        if self._expiration is None:
            try:
                with open(self._expiration_data_path) as expiration_fh:
                    self._expiration = datetime.datetime.strptime(
                        expiration_fh.read(),
                        "%Y-%m-%d %H:%M:%S.%f"
                    )
            except (ValueError, TypeError):
                LOG.warning(u._LI("Invalid data read from expiration file"))
                self.expiration = datetime.utcnow()
        return self._expiration

    @expiration.setter
    def expiration(self, val):
        with open(self._expiration_data_path, 'w') as expiration_fh:
            expiration_fh.write(val.strftime("%Y-%m-%d %H:%M:%S.%f"))
        self._expiration = val

    @property
    def host_aid(self):
        if self._host_aid is None:
            with open(self._host_aid_path) as host_aid_fh:
                self._host_aid = host_aid_fh.read()
        return self._host_aid

    @host_aid.setter
    def host_aid(self, val):
        if val is not None:
            with open(self._host_aid_path, 'w') as host_aid_fh:
                host_aid_fh.write(val)
        self._host_aid = val

    def _are_subcas_enabled_on_backend(self, connection):
        """Check if subca feature is available

        SubCA creation must be supported in both the Dogtag client as well
        as on the back-end server.  Moreover, it must be enabled on the
        backend server.  This method sets the subcas_available global variable.
        :return: True/False
        """
        global subcas_available
        if subcas_available:
            # subcas are supported in the Dogtag client
            try:
                feature_client = feature.FeatureClient(connection)
                authority_feature = feature_client.get_feature("authority")
                if authority_feature.enabled:
                    LOG.info(u._LI("Sub-CAs are enabled by Dogtag server"))
                    return True
                else:
                    LOG.info(u._LI("Sub-CAs are not enabled by Dogtag server"))
            except (request_exceptions.HTTPError,
                    pki.ResourceNotFoundException):
                LOG.info(u._LI("Sub-CAs are not supported by Dogtag server"))
        else:
            LOG.info(u._LI("Sub-CAs are not supported by Dogtag client"))
        return False

    def _get_request_id(self, order_id, plugin_meta, operation):
        request_id = plugin_meta.get(self.REQUEST_ID, None)
        if not request_id:
            raise cm.CertificateGeneralException(
                u._(
                    "{request} not found for {operation} for "
                    "order_id {order_id}"
                ).format(
                    request=self.REQUEST_ID,
                    operation=operation,
                    order_id=order_id
                )
            )
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

    def get_default_ca_name(self):
        return "Dogtag CA"

    def get_default_signing_cert(self):
        # TODO(alee) Add code to get the signing cert
        return None

    def get_default_intermediates(self):
        # TODO(alee) Add code to get the cert chain
        return None

    def check_certificate_status(self, order_id, order_meta, plugin_meta,
                                 barbican_meta_dto):
        """Check the status of a certificate request.

        :param order_id: ID of the order associated with this request
        :param order_meta: order_metadata associated with this order
        :param plugin_meta: data populated by previous calls for this order,
            in particular the request_id
        :param barbican_meta_dto: additional data needed to process order.
        :return: cm.ResultDTO
        """
        request_id = self._get_request_id(order_id, plugin_meta, "checking")

        request = self._get_request(request_id)
        if not request:
            raise cm.CertificateGeneralException(
                u._(
                    "No request found for request_id {request_id} for "
                    "order {order_id}"
                ).format(
                    request_id=request_id,
                    order_id=order_id
                )
            )

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
                    u._(
                        "Request {request_id} reports status_complete, but no "
                        "cert_id has been returned"
                    ).format(
                        request_id=request_id
                    )
                )

            cert = self._get_cert(cert_id)
            if not cert:
                raise cm.CertificateGeneralException(
                    u._("Certificate not found for cert_id: {cert_id}").format(
                        cert_id=cert_id
                    )
                )
            return cm.ResultDTO(
                cm.CertificateStatus.CERTIFICATE_GENERATED,
                certificate=cert.encoded,
                intermediates=cert.pkcs7_cert_chain)
        else:
            raise cm.CertificateGeneralException(
                u._("Invalid request_status returned by CA"))

    @_catch_request_exception
    def issue_certificate_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Issue a certificate request to the Dogtag CA

         Call the relevant certificate issuance function depending on the
         Barbican defined request type in the order_meta.

        :param order_id: ID of the order associated with this request
        :param order_meta: dict containing all the inputs for this request.
               This includes the request_type.
        :param plugin_meta: Used to store data for status check
        :param barbican_meta_dto: additional data needed to process order.
        :return: cm.ResultDTO
        """
        request_type = order_meta.get(
            cm.REQUEST_TYPE,
            cm.CertificateRequestType.CUSTOM_REQUEST)

        jump_table = {
            cm.CertificateRequestType.SIMPLE_CMC_REQUEST:
            self._issue_simple_cmc_request,
            cm.CertificateRequestType.FULL_CMC_REQUEST:
            self._issue_full_cmc_request,
            cm.CertificateRequestType.STORED_KEY_REQUEST:
            self._issue_stored_key_request,
            cm.CertificateRequestType.CUSTOM_REQUEST:
            self._issue_custom_certificate_request
        }

        if request_type not in jump_table:
            raise DogtagPluginNotSupportedException(u._(
                "Dogtag plugin does not support %s request type").format(
                    request_type))

        return jump_table[request_type](order_id, order_meta, plugin_meta,
                                        barbican_meta_dto)

    @_catch_enrollment_exceptions
    def _issue_simple_cmc_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Issue a simple CMC request to the Dogtag CA.

        :param order_id:
        :param order_meta:
        :param plugin_meta:
        :param barbican_meta_dto:
        :return: cm.ResultDTO
        """
        if barbican_meta_dto.generated_csr is not None:
            csr = barbican_meta_dto.generated_csr
        else:
            # we expect the CSR to be base64 encoded PEM
            # Dogtag CA needs it to be unencoded
            csr = base64.b64decode(order_meta.get('request_data'))

        profile_id = order_meta.get('profile', self.simple_cmc_profile)
        inputs = {
            'cert_request_type': 'pkcs10',
            'cert_request': csr
        }

        return self._issue_certificate_request(
            profile_id, inputs, plugin_meta, barbican_meta_dto)

    @_catch_enrollment_exceptions
    def _issue_full_cmc_request(self, order_id, order_meta, plugin_meta,
                                barbican_meta_dto):
        """Issue a full CMC request to the Dogtag CA.

        :param order_id:
        :param order_meta:
        :param plugin_meta:
        :param barbican_meta_dto:
        :return: cm.ResultDTO
        """
        raise DogtagPluginNotSupportedException(u._(
            "Dogtag plugin does not support %s request type").format(
                cm.CertificateRequestType.FULL_CMC_REQUEST))

    @_catch_enrollment_exceptions
    def _issue_stored_key_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Issue a simple CMC request to the Dogtag CA.

        :param order_id:
        :param order_meta:
        :param plugin_meta:
        :param barbican_meta_dto:
        :return: cm.ResultDTO
        """
        return self._issue_simple_cmc_request(
            order_id,
            order_meta,
            plugin_meta,
            barbican_meta_dto)

    @_catch_enrollment_exceptions
    def _issue_custom_certificate_request(self, order_id, order_meta,
                                          plugin_meta, barbican_meta_dto):
        """Issue a custom certificate request to Dogtag CA

        :param order_id: ID of the order associated with this request
        :param order_meta: dict containing all the inputs required for a
            particular profile.  One of these must be the profile_id.
            The exact fields (both optional and mandatory) depend on the
            profile, but they will be exposed to the user in a method to
            expose syntax.  Depending on the profile, only the relevant fields
            will be populated in the request.  All others will be ignored.
        :param plugin_meta: Used to store data for status check.
        :param barbican_meta_dto: Extra data to aid in processing.
        :return: cm.ResultDTO
        """
        profile_id = order_meta.get(self.PROFILE_ID, None)
        if not profile_id:
            return cm.ResultDTO(
                cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                status_message=u._("No profile_id specified"))

        # we expect the csr to be base64 encoded PEM data.  Dogtag CA expects
        # PEM data though so we need to decode it.
        updated_meta = copy.deepcopy(order_meta)
        if 'cert_request' in updated_meta:
            updated_meta['cert_request'] = base64.b64decode(
                updated_meta['cert_request'])

        return self._issue_certificate_request(
            profile_id, updated_meta, plugin_meta, barbican_meta_dto)

    def _issue_certificate_request(self, profile_id, inputs, plugin_meta,
                                   barbican_meta_dto):
        """Actually send the cert request to the Dogtag CA

        If the profile_id is one of the auto-approved profiles, then use
        the convenience enroll_cert() method to create and approve the request
        using the Barbican agent cert credentials.  If not, then submit the
        request and wait for approval by a CA agent on the Dogtag CA.

        :param profile_id: enrollment profile
        :param inputs: dict of request inputs
        :param plugin_meta: Used to store data for status check.
        :param barbican_meta_dto: Extra data to aid in processing.
        :return: cm.ResultDTO
        """
        ca_id = barbican_meta_dto.plugin_ca_id or self.get_default_ca_name()

        if profile_id in self.auto_approved_profiles:
            if ca_id == self.get_default_ca_name():
                results = self.certclient.enroll_cert(profile_id, inputs)
            else:
                results = self.certclient.enroll_cert(
                    profile_id, inputs, ca_id)
            return self._process_auto_enrollment_results(
                results, plugin_meta, barbican_meta_dto)
        else:
            request = self.certclient.create_enrollment_request(
                profile_id, inputs)
            if ca_id == self.get_default_ca_name():
                results = self.certclient.submit_enrollment_request(request)
            else:
                results = self.certclient.submit_enrollment_request(
                    request, ca_id)
            return self._process_pending_enrollment_results(
                results, plugin_meta, barbican_meta_dto)

    def _process_auto_enrollment_results(self, enrollment_results,
                                         plugin_meta, barbican_meta_dto):
        """Process results received from Dogtag CA for auto-enrollment

        This processes data from enroll_cert, which submits, approves and
        gets the cert issued and returns as a list of CertEnrollment objects.

        :param enrollment_results: list of CertEnrollmentResult objects
        :param plugin_meta: metadata dict for storing plugin specific data
        :param barbican_meta_dto: object containing extra data to help process
               the request
        :return: cm.ResultDTO
        """

        # Although it is possible to create multiple certs in an invocation
        # of enroll_cert, Barbican cannot handle this case.  Assume
        # only once cert and request generated for now.
        enrollment_result = enrollment_results[0]
        request = enrollment_result.request
        if not request:
            raise cm.CertificateGeneralException(
                u._("No request returned in enrollment_results"))

        # store the request_id in the plugin metadata
        plugin_meta[self.REQUEST_ID] = request.request_id

        cert = enrollment_result.cert

        return self._create_dto(request.request_status,
                                request.request_id,
                                request.error_message,
                                cert)

    def _process_pending_enrollment_results(self, results, plugin_meta,
                                            barbican_meta_dto):
        """Process results received from Dogtag CA for pending enrollment

        This method processes data returned by submit_enrollment_request(),
        which creates requests that still need to be approved by an agent.

        :param results: CertRequestInfoCollection object
        :param plugin_meta: metadata dict for storing plugin specific data
        :param barbican_meta_dto: object containing extra data to help process
               the request
        :return: cm.ResultDTO
        """

        # Although it is possible to create multiple certs in an invocation
        # of enroll_cert, Barbican cannot handle this case.  Assume
        # only once cert and request generated for now

        cert_request_info = results.cert_request_info_list[0]
        status = cert_request_info.request_status
        request_id = getattr(cert_request_info, 'request_id', None)
        error_message = getattr(cert_request_info, 'error_message', None)

        # store the request_id in the plugin metadata
        if request_id:
            plugin_meta[self.REQUEST_ID] = request_id

        return self._create_dto(status, request_id, error_message, None)

    def _create_dto(self, request_status, request_id, error_message, cert):
        dto = None
        if request_status == pki.cert.CertRequestStatus.COMPLETE:
            if cert is not None:
                # Barbican is expecting base 64 encoded PEM, so we base64
                # encode below.
                #
                # Currently there is an inconsistency in what Dogtag returns
                # for certificates and intermediates.  For certs, we return
                # PEM, whereas for intermediates, we return headerless PEM.
                # This is being addressed in Dogtag ticket:
                # https://fedorahosted.org/pki/ticket/1374
                #
                # Until this is addressed, simply add the missing headers
                cert_chain = (CERT_HEADER + "\r\n" + cert.pkcs7_cert_chain +
                              CERT_FOOTER)

                dto = cm.ResultDTO(cm.CertificateStatus.CERTIFICATE_GENERATED,
                                   certificate=base64.b64encode(cert.encoded),
                                   intermediates=base64.b64encode(cert_chain))
            else:
                raise cm.CertificateGeneralException(
                    u._("request_id {req_id} returns COMPLETE but no cert "
                        "returned").format(req_id=request_id))

        elif request_status == pki.cert.CertRequestStatus.REJECTED:
            dto = cm.ResultDTO(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                               status_message=error_message)
        elif request_status == pki.cert.CertRequestStatus.CANCELED:
            dto = cm.ResultDTO(cm.CertificateStatus.REQUEST_CANCELED)
        elif request_status == pki.cert.CertRequestStatus.PENDING:
            dto = cm.ResultDTO(cm.CertificateStatus.WAITING_FOR_CA)
        else:
            raise cm.CertificateGeneralException(
                u._("Invalid request_status {status} for "
                    "request_id {request_id}").format(
                        status=request_status,
                        request_id=request_id)
            )

        return dto

    def modify_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
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
        :param barbican_meta_dto: additional data needed to process order.
        :return: ResultDTO:
        """
        result_dto = self.cancel_certificate_request(
            order_id, order_meta, plugin_meta, barbican_meta_dto)

        if result_dto.status == cm.CertificateStatus.REQUEST_CANCELED:
            return self.issue_certificate_request(
                order_id, order_meta, plugin_meta, barbican_meta_dto)
        elif result_dto.status == cm.CertificateStatus.INVALID_OPERATION:
            return cm.ResultDTO(
                cm.CertificateStatus.INVALID_OPERATION,
                status_message=u._(
                    "Modify request: unable to cancel: "
                    "{message}").format(message=result_dto.status_message)
            )
        else:
            # other status (ca_unavailable, client_data_issue)
            # return result from cancel operation
            return result_dto

    @_catch_request_exception
    def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Cancel a certificate request.

        :param order_id: ID for the order associated with this request
        :param order_meta: order metadata fdr this request
        :param plugin_meta: data stored by plugin for further processing.
            In particular, the request_id
        :param barbican_meta_dto: additional data needed to process order.
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
                status_message=u._("no request found for this order"))
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

    def supported_request_types(self):
        """Returns the request_types supported by this plugin.

        :returns: a list of the Barbican-core defined request_types
                  supported by this plugin.
        """
        return [cm.CertificateRequestType.SIMPLE_CMC_REQUEST,
                cm.CertificateRequestType.STORED_KEY_REQUEST,
                cm.CertificateRequestType.CUSTOM_REQUEST]

    def supports_create_ca(self):
        """Returns if this plugin and the backend CA supports subCAs

        :return: True/False
        """
        return subcas_available

    @_catch_subca_creation_exceptions
    def create_ca(self, ca_create_dto):
        """Creates a subordinate CA upon request

        :param ca_create_dto:
            Data transfer object :class:`CACreateDTO` containing data
            required to generate a subordinate CA.  This data includes
            the subject DN of the new CA signing certificate, a name for
            the new CA and a reference to the CA that will issue the new
            subordinate CA's signing certificate,

        :return: ca_info:
            Dictionary containing the data needed to create a
            models.CertificateAuthority object
        """
        if not subcas_available:
            raise exception.SubCAsNotSupported(
                "Subordinate CAs are not supported by this Dogtag CA")

        parent_ca_id = self._get_correct_ca_id(ca_create_dto.parent_ca_id)
        ca_data = authority.AuthorityData(
            dn=ca_create_dto.subject_dn,
            parent_aid=parent_ca_id,
            description=ca_create_dto.name)

        new_ca_data = self.authority_client.create_ca(ca_data)

        cert = self.authority_client.get_cert(new_ca_data.aid, "PEM")
        chain = self.authority_client.get_chain(new_ca_data.aid, "PEM")

        return {
            cm.INFO_NAME: new_ca_data.description,
            cm.INFO_CA_SIGNING_CERT: cert,
            cm.INFO_EXPIRATION: self.expiration.isoformat(),
            cm.INFO_INTERMEDIATES: chain,
            cm.PLUGIN_CA_ID: new_ca_data.aid
        }

    def _get_correct_ca_id(self, plugin_ca_id):
        """Returns the correct authority id

        When the Dogtag plugin updates its CA list, any subcas will
        have a plugin_ca_id that matches the authority_id (aid) as
        returned from the backend CA.

        For migration purposes, though, ie. migrating from a non-subca
        environment to a subca one, we want the host CA to keep the same
        plugin_ca_id (which is the default_ca_name) so that no disruption
        occurs.  Therefore, we need to store the host CA's authority ID
        (in get_ca_info) and return it here instead.
        """
        if plugin_ca_id == self.get_default_ca_name():
            return self.host_aid
        else:
            return plugin_ca_id

    @_catch_subca_deletion_exceptions
    def delete_ca(self, ca_id):
        """Deletes a subordinate CA

        :param ca_id: id for the CA as specified by the plugin
        :return: None
        """
        if not subcas_available:
            raise exception.SubCAsNotSupported(
                "Subordinate CAs are not supported by this Dogtag CA")

        # ca must be disabled first
        self.authority_client.disable_ca(ca_id)
        self.authority_client.delete_ca(ca_id)

    def get_ca_info(self):
        if not subcas_available:
            return super(DogtagCAPlugin, self).get_ca_info()

        self.expiration = (datetime.datetime.utcnow() + datetime.timedelta(
            days=int(self._expiration_delta)))

        ret = {}
        cas = self.authority_client.list_cas()
        for ca_data in cas.ca_list:
            if not ca_data.enabled:
                continue

            cert = self.authority_client.get_cert(ca_data.aid, "PEM")
            chain = self.authority_client.get_chain(ca_data.aid, "PEM")
            ca_info = {
                cm.INFO_NAME: ca_data.description,
                cm.INFO_CA_SIGNING_CERT: cert,
                cm.INFO_INTERMEDIATES: chain,
                cm.INFO_EXPIRATION: self.expiration.isoformat()
            }

            # handle the migration case.  The top level CA should continue
            # to work as before

            if ca_data.is_host_authority:
                ret[self.get_default_ca_name()] = ca_info
                self.host_aid = ca_data.aid
            else:
                ret[ca_data.aid] = ca_info

        return ret

    def get_host_aid(self):
        cas = self.authority_client.list_cas()
        for ca_data in cas.ca_list:
            if ca_data.is_host_authority:
                return ca_data.aid
        return None
