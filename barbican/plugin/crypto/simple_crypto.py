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

from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from cryptography import fernet
from oslo_config import cfg
import six

from barbican import i18n as u
from barbican.plugin.crypto import crypto as c


CONF = cfg.CONF

simple_crypto_plugin_group = cfg.OptGroup(name='simple_crypto_plugin',
                                          title="Simple Crypto Plugin Options")
simple_crypto_plugin_opts = [
    cfg.StrOpt('kek',
               default=b'dGhpcnR5X3R3b19ieXRlX2tleWJsYWhibGFoYmxhaGg=',
               help=u._('Key encryption key to be used by Simple Crypto '
                        'Plugin'))
]
CONF.register_group(simple_crypto_plugin_group)
CONF.register_opts(simple_crypto_plugin_opts, group=simple_crypto_plugin_group)


class SimpleCryptoPlugin(c.CryptoPluginBase):
    """Insecure implementation of the crypto plugin."""

    def __init__(self, conf=CONF):
        self.master_kek = conf.simple_crypto_plugin.kek

    def _get_kek(self, kek_meta_dto):
        if not kek_meta_dto.plugin_meta:
            raise ValueError(u._('KEK not yet created.'))
        # the kek is stored encrypted. Need to decrypt.
        encryptor = fernet.Fernet(self.master_kek)
        # Note : If plugin_meta type is unicode, encode to byte.
        if isinstance(kek_meta_dto.plugin_meta, six.text_type):
            kek_meta_dto.plugin_meta = kek_meta_dto.plugin_meta.encode('utf-8')

        return encryptor.decrypt(kek_meta_dto.plugin_meta)

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        kek = self._get_kek(kek_meta_dto)
        unencrypted = encrypt_dto.unencrypted
        if not isinstance(unencrypted, str):
            raise ValueError(
                u._(
                    'Unencrypted data must be a byte type, but was '
                    '{unencrypted_type}'
                ).format(
                    unencrypted_type=type(unencrypted)
                )
            )
        encryptor = fernet.Fernet(kek)
        cyphertext = encryptor.encrypt(unencrypted)
        return c.ResponseDTO(cyphertext, None)

    def decrypt(self, encrypted_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        kek = self._get_kek(kek_meta_dto)
        encrypted = encrypted_dto.encrypted
        decryptor = fernet.Fernet(kek)
        return decryptor.decrypt(encrypted)

    def bind_kek_metadata(self, kek_meta_dto):
        kek_meta_dto.algorithm = 'aes'
        kek_meta_dto.bit_length = 128
        kek_meta_dto.mode = 'cbc'
        if not kek_meta_dto.plugin_meta:
            # the kek is stored encrypted in the plugin_meta field
            encryptor = fernet.Fernet(self.master_kek)
            key = fernet.Fernet.generate_key()
            kek_meta_dto.plugin_meta = encryptor.encrypt(key)
        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        byte_length = int(generate_dto.bit_length) / 8
        unencrypted = os.urandom(byte_length)

        return self.encrypt(c.EncryptDTO(unencrypted),
                            kek_meta_dto,
                            project_id)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, project_id):
        """Generate asymmetric keys based on below rules:

        - RSA, with passphrase (supported)
        - RSA, without passphrase (supported)
        - DSA, without passphrase (supported)
        - DSA, with passphrase (not supported)

        Note: PyCrypto is not capable of serializing DSA
        keys and DER formated keys. Such keys will be
        serialized to Base64 PEM to store in DB.

        TODO (atiwari/reaperhulk): PyCrypto is not capable to serialize
        DSA keys and DER formated keys, later we need to pick better
        crypto lib.
        """
        if(generate_dto.algorithm is None or generate_dto
                .algorithm.lower() == 'rsa'):
            private_key = RSA.generate(
                generate_dto.bit_length, None, None, 65537)
        elif generate_dto.algorithm.lower() == 'dsa':
            private_key = DSA.generate(generate_dto.bit_length, None, None)
        else:
            raise c.CryptoPrivateKeyFailureException()

        public_key = private_key.publickey()

        # Note (atiwari): key wrapping format PEM only supported
        if generate_dto.algorithm.lower() == 'rsa':
            public_key, private_key = self._wrap_key(public_key, private_key,
                                                     generate_dto.passphrase)
        if generate_dto.algorithm.lower() == 'dsa':
            if generate_dto.passphrase:
                raise ValueError(u._('Passphrase not supported for DSA key'))
            public_key, private_key = self._serialize_dsa_key(public_key,
                                                              private_key)
        private_dto = self.encrypt(c.EncryptDTO(private_key),
                                   kek_meta_dto,
                                   project_id)

        public_dto = self.encrypt(c.EncryptDTO(public_key),
                                  kek_meta_dto,
                                  project_id)

        passphrase_dto = None
        if generate_dto.passphrase:
            if isinstance(generate_dto.passphrase, six.text_type):
                generate_dto.passphrase = generate_dto.passphrase.encode(
                    'utf-8')

            passphrase_dto = self.encrypt(c.EncryptDTO(generate_dto.
                                                       passphrase),
                                          kek_meta_dto,
                                          project_id)

        return private_dto, public_dto, passphrase_dto

    def supports(self, type_enum, algorithm=None, bit_length=None,
                 mode=None):
        if type_enum == c.PluginSupportTypes.ENCRYPT_DECRYPT:
            return True

        if type_enum == c.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length)
        elif type_enum == c.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length)
        else:
            return False

    def _wrap_key(self, public_key, private_key,
                  passphrase):
        pkcs = 8
        key_wrap_format = 'DER'

        private_key = private_key.exportKey(key_wrap_format, passphrase, pkcs)
        public_key = public_key.exportKey(key_wrap_format)

        return public_key, private_key

    def _serialize_dsa_key(self, public_key, private_key):

        pub_seq = asn1.DerSequence()
        pub_seq[:] = [0, public_key.p, public_key.q,
                      public_key.g, public_key.y]
        public_key = pub_seq.encode()

        prv_seq = asn1.DerSequence()
        prv_seq[:] = [0, private_key.p, private_key.q,
                      private_key.g, private_key.y, private_key.x]
        private_key = prv_seq.encode()

        return public_key, private_key

    def _is_algorithm_supported(self, algorithm=None, bit_length=None):
        """check if algorithm and bit_length combination is supported."""
        if algorithm is None or bit_length is None:
            return False

        if (algorithm.lower() in
                c.PluginSupportTypes.SYMMETRIC_ALGORITHMS and bit_length in
                c.PluginSupportTypes.SYMMETRIC_KEY_LENGTHS):
            return True
        elif (algorithm.lower() in c.PluginSupportTypes.ASYMMETRIC_ALGORITHMS
              and bit_length in c.PluginSupportTypes.ASYMMETRIC_KEY_LENGTHS):
            return True
        else:
            return False
