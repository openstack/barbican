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
import os
import uuid

from oslo.config import cfg
import pki
from pki.client import PKIConnection
import pki.cryptoutil as cryptoutil
import pki.key as key
from pki.kraclient import KRAClient

from barbican.common import exception
from barbican.crypto import plugin
from barbican.openstack.common import gettextutils as u

CONF = cfg.CONF

dogtag_crypto_plugin_group = cfg.OptGroup(name='dogtag_crypto_plugin',
                                          title="Dogtag Crypto Plugin Options")
dogtag_crypto_plugin_opts = [
    cfg.StrOpt('pem_path',
               default=None,
               help=u._('Path to PEM file for authentication')),
    cfg.StrOpt('pem_password',
               default=None,
               help=u._('Password to unlock PEM file')),
    cfg.StrOpt('drm_host',
               default="localhost",
               help=u._('Hostname for the DRM')),
    cfg.StrOpt('drm_port',
               default="8443",
               help=u._('Port for the DRM')),
    cfg.StrOpt('nss_db_path',
               default=None,
               help=u._('Path to the NSS certificate database')),
    cfg.StrOpt('nss_password',
               default=None,
               help=u._('Password for NSS certificate database'))
]

CONF.register_group(dogtag_crypto_plugin_group)
CONF.register_opts(dogtag_crypto_plugin_opts, group=dogtag_crypto_plugin_group)


class DogtagPluginAlgorithmException(exception.BarbicanException):
    message = u._("Invalid algorithm passed in")


class DogtagCryptoPlugin(plugin.CryptoPluginBase):
    """Dogtag implementation of the crypto plugin with DRM as the backend."""

    TRANSPORT_NICK = "DRM transport cert"

    def __init__(self, conf=CONF):
        """Constructor - create the keyclient."""
        pem_path = conf.dogtag_crypto_plugin.pem_path
        if pem_path is None:
            raise ValueError(u._("pem_path is required"))

        pem_password = conf.dogtag_crypto_plugin.pem_password
        if pem_password is None:
            raise ValueError(u._("pem_password is required"))

        crypto = None
        create_nss_db = False

        nss_db_path = conf.dogtag_crypto_plugin.nss_db_path
        if nss_db_path is not None:
            nss_password = conf.dogtag_crypto_plugin.nss_password
            if nss_password is None:
                raise ValueError(u._("nss_password is required"))

            if not os.path.exists(nss_db_path):
                create_nss_db = True
                cryptoutil.NSSCryptoUtil.setup_database(
                    nss_db_path, nss_password, over_write=True)

            crypto = cryptoutil.NSSCryptoUtil(nss_db_path, nss_password)

        # set up connection
        connection = PKIConnection('https',
                                   conf.dogtag_crypto_plugin.drm_host,
                                   conf.dogtag_crypto_plugin.drm_port,
                                   'kra')
        connection.set_authentication_cert(pem_path)

        # what happened to the password?
        # until we figure out how to pass the password to requests, we'll
        # just use -nodes to create the admin cert pem file.  Any required
        # code will end up being in the DRM python client

        #create kraclient
        kraclient = KRAClient(connection, crypto)
        self.keyclient = kraclient.keys
        self.systemcert_client = kraclient.system_certs

        if crypto is not None:
            if create_nss_db:
                # Get transport cert and insert in the certdb
                transport_cert = self.systemcert_client.get_transport_cert()
                tcert = transport_cert[
                    len(pki.CERT_HEADER):
                    len(transport_cert) - len(pki.CERT_FOOTER)]
                crypto.import_cert(DogtagCryptoPlugin.TRANSPORT_NICK,
                                   base64.decodestring(tcert), "u,u,u")

            crypto.initialize()
            self.keyclient.set_transport_cert(
                DogtagCryptoPlugin.TRANSPORT_NICK)

    def encrypt(self, encrypt_dto, kek_meta_dto, keystone_id):
        """Store a secret in the DRM

        This will likely require another parameter which includes the wrapped
        session key to be passed.  Until that is added, we will call
        archive_key() which relies on the DRM python client to create the
        session keys.

        We may also be able to be more specific in terms of the data_type
        if we know that the data being stored is a symmetric key.  Until
        then, we need to assume that the secret is pass_phrase_type.
        """
        data_type = key.KeyClient.PASS_PHRASE_TYPE
        client_key_id = uuid.uuid4().hex
        response = self.keyclient.archive_key(client_key_id,
                                              data_type,
                                              encrypt_dto.unencrypted,
                                              key_algorithm=None,
                                              key_size=None)
        return plugin.ResponseDTO(response.get_key_id(), None)

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                keystone_id):
        """Retrieve a secret from the DRM

        The encrypted parameter simply contains the plain text key_id by which
        the secret is known to the DRM.  The remaining parameters are not
        used.

        Note: There are two ways to retrieve secrets from the DRM.

        The first, which is implemented here, will call retrieve_key without
        a wrapping key.  This relies on the DRM client to generate a wrapping
        key (and wrap it with the DRM transport cert), and is completely
        transparent to the Barbican server.  What is returned to the caller
        is the unencrypted secret.

        The second way is to provide a wrapping key that ideally would be
        generated on the barbican client.  That way only the client will be
        able to unwrap the secret.  This is not yet implemented because
        decrypt() and the barbican API still need to be changed to pass the
        wrapping key.
        """
        key_id = decrypt_dto.encrypted
        key = self.keyclient.retrieve_key(key_id)
        return key.data

    def bind_kek_metadata(self, kek_meta_dto):
        """This function is not used by this plugin."""
        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, keystone_id):
        """Generate a symmetric key

        This calls generate_symmetric_key() on the DRM passing in the
        algorithm, bit_length and id (used as the client_key_id) from
        the secret.  The remaining parameters are not used.

        Returns a keyId which will be stored in an EncryptedDatum
        table for later retrieval.
        """

        usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE,
                  key.SymKeyGenerationRequest.ENCRYPT_USAGE]

        client_key_id = uuid.uuid4().hex
        algorithm = self._map_algorithm(generate_dto.algorithm.lower())

        if algorithm is None:
            raise DogtagPluginAlgorithmException

        response = self.keyclient.generate_symmetric_key(
            client_key_id,
            algorithm,
            generate_dto.bit_length,
            usages)
        return plugin.ResponseDTO(response.get_key_id(), None)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, keystone_id):
        """Generate an asymmetric key."""
        raise NotImplementedError("Feature not implemented for dogtag crypto")

    def supports(self, type_enum, algorithm=None, bit_length=None,
                 mode=None):
        """Specifies what operations the plugin supports."""
        if type_enum == plugin.PluginSupportTypes.ENCRYPT_DECRYPT:
            return True
        elif type_enum == plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length)
        elif type_enum == plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION:
            return False
        else:
            return False

    @staticmethod
    def _map_algorithm(algorithm):
        """Map Barbican algorithms to Dogtag plugin algorithms."""
        if algorithm == "aes":
            return key.KeyClient.AES_ALGORITHM
        elif algorithm == "des":
            return key.KeyClient.DES_ALGORITHM
        elif algorithm == "3des":
            return key.KeyClient.DES3_ALGORITHM
        else:
            return None

    def _is_algorithm_supported(self, algorithm, bit_length=None):
        """Check if algorithm and bit length are supported

        For now, we will just check the algorithm. When dogtag adds a
        call to check the bit length per algorithm, we can modify to
        make that call
        """
        return self._map_algorithm(algorithm) is not None
