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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from oslo_utils import uuidutils
import time

import pki
import pki.client
import pki.crypto as cryptoutil
import pki.key as key
import pki.kra
import pki.profile

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u

# we want to keep the dogtag config options separated. That way we
# do not need to import every dogtag requirement to generate the
# sample config
import barbican.plugin.dogtag_config_opts  # noqa
import barbican.plugin.interface.secret_store as sstore

# reuse the conf object to not call config.new_config() twice
CONF = barbican.plugin.dogtag_config_opts.CONF
LOG = utils.getLogger(__name__)

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
        LOG.info("The nss_db_path provided already exists, so the "
                 "database is assumed to be already set up.")
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
        LOG.warning("nss_db_path was not provided so the crypto "
                    "provider functions were not initialized.")
        return None
    if nss_password is None:
        raise ValueError(u._("nss_password is required"))
    if type(nss_password) is not bytes:
        # Password needs to be a bytes object in Python 3
        nss_password = nss_password.encode('UTF-8')

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
        crypto.import_cert(KRA_TRANSPORT_NICK, transport_cert, ",,")
    except Exception as e:
        LOG.debug("Error importing KRA transport cert.", exc_info=True)
        LOG.error("Error in importing transport cert."
                  " KRA may not be enabled: %s", e)


def create_connection(conf, subsystem_path):
    pem_path = conf.dogtag_plugin.pem_path
    if pem_path is None:
        raise ValueError(u._("pem_path is required"))
    # port is string type in PKIConnection
    connection = pki.client.PKIConnection(
        'https',
        conf.dogtag_plugin.dogtag_host,
        str(conf.dogtag_plugin.dogtag_port),
        subsystem_path)
    connection.set_authentication_cert(pem_path)
    return connection


crypto = _setup_nss_db_services(CONF)
if crypto:
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


class DogtagPluginArchivalException(exception.BarbicanException):
    message = u._("Key archival failed.  Error returned from KRA.")


class DogtagPluginGenerationException(exception.BarbicanException):
    message = u._("Key generation failed.  Error returned from KRA.")


class DogtagKRAPlugin(sstore.SecretStoreBase):
    """Implementation of the secret store plugin with KRA as the backend."""

    # metadata constants
    ALG = "alg"
    BIT_LENGTH = "bit_length"
    GENERATED = "generated"
    KEY_ID = "key_id"
    SECRET_MODE = "secret_mode"  # nosec
    PASSPHRASE_KEY_ID = "passphrase_key_id"  # nosec
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
        self.plugin_name = conf.dogtag_plugin.plugin_name
        self.retries = conf.dogtag_plugin.retries

        LOG.debug("completed DogtagKRAPlugin init")

    def get_plugin_name(self):
        return self.plugin_name

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
        key_id = None

        attempts = 0
        offset_time = 1
        while attempts <= self.retries and key_id is None:
            client_key_id = uuidutils.generate_uuid(dashed=False)
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

            key_id = response.get_key_id()

            if key_id is None:
                LOG.warning("key_id is None.  attempts: {}".format(attempts))
                attempts += 1
                time.sleep(offset_time)
                offset_time += 1

        if key_id is None:
            raise DogtagPluginArchivalException

        meta_dict = {DogtagKRAPlugin.KEY_ID: key_id}

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

                key_info = self.keyclient.get_key_info(key_id)
                recovered_key = serialization.load_der_public_key(
                    key_info.public_key,
                    backend=default_backend()
                ).public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.PKCS1)

            elif secret_type == sstore.SecretType.PRIVATE:
                key_data = self.keyclient.retrieve_key(key_id)
                private_key = serialization.load_der_private_key(
                    key_data.data,
                    password=None,
                    backend=default_backend()
                )

                if passphrase is not None:
                    e_alg = serialization.BestAvailableEncryption(passphrase)
                else:
                    e_alg = serialization.NoEncryption()

                recovered_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=e_alg
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

        algorithm = self._map_algorithm(key_spec.alg.lower())

        if algorithm is None:
            raise DogtagPluginAlgorithmException
        passphrase = key_spec.passphrase
        if passphrase:
            raise DogtagPluginNotSupportedException(
                u._("Passphrase encryption is not supported for symmetric"
                    " key generating algorithms."))

        key_id = None
        attempts = 0
        offset_time = 1
        while attempts <= self.retries and key_id is None:
            client_key_id = uuidutils.generate_uuid()
            response = self.keyclient.generate_symmetric_key(
                client_key_id,
                algorithm,
                key_spec.bit_length,
                usages)
            key_id = response.get_key_id()

            if key_id is None:
                LOG.warning("generate_symkey: key_id is None.  attempts: {}"
                            .format(attempts))
                attempts += 1
                time.sleep(offset_time)
                offset_time += 1

        if key_id is None:
            raise DogtagPluginGenerationException

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
                DogtagKRAPlugin.KEY_ID: response.get_key_id(),
                DogtagKRAPlugin.GENERATED: True}

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key.

        Note that barbican expects all secrets to be base64 encoded.
        """

        usages = [key.AsymKeyGenerationRequest.DECRYPT_USAGE,
                  key.AsymKeyGenerationRequest.ENCRYPT_USAGE]

        client_key_id = uuidutils.generate_uuid()
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
                uuidutils.generate_uuid(),
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
