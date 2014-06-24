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
import pki.client
import pki.cryptoutil as cryptoutil
import pki.key as key
import pki.kraclient

from barbican.common import exception
from barbican.openstack.common import gettextutils as u
import barbican.plugin.interface.secret_store as sstore

CONF = cfg.CONF

dogtag_plugin_group = cfg.OptGroup(name='dogtag_plugin',
                                   title="Dogtag Plugin Options")
dogtag_plugin_opts = [
    cfg.StrOpt('pem_path',
               help=u._('Path to PEM file for authentication')),
    cfg.StrOpt('pem_password',
               help=u._('Password to unlock PEM file')),
    cfg.StrOpt('drm_host',
               default="localhost",
               help=u._('Hostname for the DRM')),
    cfg.StrOpt('drm_port',
               default="8443",
               help=u._('Port for the DRM')),
    cfg.StrOpt('nss_db_path',
               help=u._('Path to the NSS certificate database')),
    cfg.StrOpt('nss_password',
               help=u._('Password for NSS certificate database'))
]

CONF.register_group(dogtag_plugin_group)
CONF.register_opts(dogtag_plugin_opts, group=dogtag_plugin_group)


class DogtagPluginAlgorithmException(exception.BarbicanException):
    message = u._("Invalid algorithm passed in")


class DogtagPlugin(sstore.SecretStoreBase):
    """Implementation of the secret store plugin with DRM as the backend."""

    TRANSPORT_NICK = "DRM transport cert"

    # metadata constants
    KEY_ID = "key_id"
    SECRET_TYPE = "secret_type"
    SECRET_FORMAT = "secret_format"
    SECRET_KEYSPEC = "secret_keyspec"

    def __init__(self, conf=CONF):
        """Constructor - create the keyclient."""
        pem_path = conf.dogtag_plugin.pem_path
        if pem_path is None:
            raise ValueError(u._("pem_path is required"))

        pem_password = conf.dogtag_plugin.pem_password
        if pem_password is None:
            raise ValueError(u._("pem_password is required"))

        crypto = None
        create_nss_db = False

        nss_db_path = conf.dogtag_plugin.nss_db_path
        if nss_db_path is not None:
            nss_password = conf.dogtag_plugin.nss_password
            if nss_password is None:
                raise ValueError(u._("nss_password is required"))

            if not os.path.exists(nss_db_path):
                create_nss_db = True
                cryptoutil.NSSCryptoUtil.setup_database(
                    nss_db_path, nss_password, over_write=True)

            crypto = cryptoutil.NSSCryptoUtil(nss_db_path, nss_password)

        # set up connection
        connection = pki.client.PKIConnection(
            'https',
            conf.dogtag_plugin.drm_host,
            conf.dogtag_plugin.drm_port,
            'kra')
        connection.set_authentication_cert(pem_path)

        # what happened to the password?
        # until we figure out how to pass the password to requests, we'll
        # just use -nodes to create the admin cert pem file.  Any required
        # code will end up being in the DRM python client

        #create kraclient
        kraclient = pki.kraclient.KRAClient(connection, crypto)
        self.keyclient = kraclient.keys
        self.systemcert_client = kraclient.system_certs

        if crypto is not None:
            if create_nss_db:
                # Get transport cert and insert in the certdb
                transport_cert = self.systemcert_client.get_transport_cert()
                tcert = transport_cert[
                    len(pki.CERT_HEADER):
                    len(transport_cert) - len(pki.CERT_FOOTER)]
                crypto.import_cert(DogtagPlugin.TRANSPORT_NICK,
                                   base64.decodestring(tcert), "u,u,u")

            crypto.initialize()
            self.keyclient.set_transport_cert(
                DogtagPlugin.TRANSPORT_NICK)

    def store_secret(self, secret_dto):
        """Store a secret in the DRM

        This will likely require another parameter which includes the wrapped
        session key to be passed.  Until that is added, we will call
        archive_key() which relies on the DRM python client to create the
        session keys.

        The secret_dto contains additional information on the type of secret
        that is being stored.  We will use that shortly.  For, now, lets just
        assume that its all PASS_PHRASE_TYPE

        Returns a dict with the relevant metadata (which in this case is just
        the key_id
        """
        data_type = key.KeyClient.PASS_PHRASE_TYPE
        client_key_id = uuid.uuid4().hex
        response = self.keyclient.archive_key(client_key_id,
                                              data_type,
                                              secret_dto.secret,
                                              key_algorithm=None,
                                              key_size=None)
        return {DogtagPlugin.SECRET_TYPE: secret_dto.type,
                DogtagPlugin.SECRET_FORMAT: secret_dto.format,
                DogtagPlugin.SECRET_KEYSPEC: secret_dto.key_spec,
                DogtagPlugin.KEY_ID: response.get_key_id()}

    def get_secret(self, secret_metadata):
        """Retrieve a secret from the DRM

        The secret_metadata is simply the dict returned by a store_secret() or
        get_secret() call.  We will extract the key_id from this dict.

        Note: There are two ways to retrieve secrets from the DRM.

        The first, which is implemented here, will call retrieve_key without
        a wrapping key.  This relies on the DRM client to generate a wrapping
        key (and wrap it with the DRM transport cert), and is completely
        transparent to the Barbican server.  What is returned to the caller
        is the unencrypted secret.

        The second way is to provide a wrapping key that ideally would be
        generated on the barbican client.  That way only the client will be
        able to unwrap the secret.  This is not yet implemented (but will be
        shortly)
        """
        key_id = secret_metadata[DogtagPlugin.KEY_ID]

        recovered_key = self.keyclient.retrieve_key(key_id)
        ret = sstore.SecretDTO(secret_metadata[DogtagPlugin.SECRET_TYPE],
                               secret_metadata[DogtagPlugin.SECRET_FORMAT],
                               recovered_key,
                               secret_metadata[DogtagPlugin.SECRET_KEYSPEC])

        return ret

    def delete_secret(self, secret_metadata):
        """Delete a secret from the DRM

        There is currently no way to delete a secret in Dogtag.
        We will be implementing such a method shortly.
        """
        pass

    def generate_symmetric_key(self, key_spec):
        """Generate a symmetric key

        This calls generate_symmetric_key() on the DRM passing in the
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

        response = self.keyclient.generate_symmetric_key(
            client_key_id,
            algorithm,
            key_spec.bit_length,
            usages)
        return {DogtagPlugin.SECRET_KEYSPEC: key_spec,
                DogtagPlugin.SECRET_FORMAT: sstore.KeyFormat.RAW,
                DogtagPlugin.SECRET_TYPE: sstore.SecretType.SYMMETRIC,
                DogtagPlugin.KEY_ID: response.get_key_id()}

    def generate_asymmetric_key(self, key_spec):
        """Generate an asymmetric key."""
        raise NotImplementedError(
            "Feature not yet implemented by dogtag plugin")

    def generate_supports(self, key_spec):
        """Key generation supported?

        Specifies whether the plugin supports key generation with the
        given key_spec.

        For now, we will just check the algorithm.  When dogtag adds a
        call to check the bit length as well, we will use that call to
        take advantage of the bit_length information
        """
        return self._map_algorithm(key_spec.alg) is not None

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
        elif algorithm == sstore.KeyAlgorithm.DIFFIE_HELLMAN:
            # may be supported, needs to be tested
            return None
        elif algorithm == sstore.KeyAlgorithm.DSA:
            # may be supported, needs to be tested
            return None
        elif algorithm == sstore.KeyAlgorithm.EC:
            # asymmetric keys not yet supported
            return None
        elif algorithm == sstore.KeyAlgorithm.RSA:
            #asymmetric keys not yet supported
            return None
        else:
            return None
