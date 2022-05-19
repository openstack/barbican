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

from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from oslo_config import cfg
from oslo_utils import encodeutils

from barbican.common import config
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin.crypto import base as c


CONF = config.new_config()
LOG = utils.getLogger(__name__)

simple_crypto_plugin_group = cfg.OptGroup(name='simple_crypto_plugin',
                                          title="Simple Crypto Plugin Options")
simple_crypto_plugin_opts = [
    cfg.StrOpt('kek',
               default='dGhpcnR5X3R3b19ieXRlX2tleWJsYWhibGFoYmxhaGg=',
               help=u._('Key encryption key to be used by Simple Crypto '
                        'Plugin'), secret=True),
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='Software Only Crypto'),
]
CONF.register_group(simple_crypto_plugin_group)
CONF.register_opts(simple_crypto_plugin_opts, group=simple_crypto_plugin_group)
config.parse_args(CONF)


def list_opts():
    yield simple_crypto_plugin_group, simple_crypto_plugin_opts


class SimpleCryptoPlugin(c.CryptoPluginBase):
    """Insecure implementation of the crypto plugin."""

    def __init__(self, conf=CONF):
        self.master_kek = conf.simple_crypto_plugin.kek
        self.plugin_name = conf.simple_crypto_plugin.plugin_name
        LOG.info("{} initialized".format(self.plugin_name))

    def get_plugin_name(self):
        return self.plugin_name

    def _get_kek(self, kek_meta_dto):
        if not kek_meta_dto.plugin_meta:
            raise ValueError(u._('KEK not yet created.'))
        # the kek is stored encrypted. Need to decrypt.
        encryptor = fernet.Fernet(self.master_kek)
        # Note : If plugin_meta type is unicode, encode to byte.
        if isinstance(kek_meta_dto.plugin_meta, str):
            kek_meta_dto.plugin_meta = kek_meta_dto.plugin_meta.encode('utf-8')

        return encryptor.decrypt(kek_meta_dto.plugin_meta)

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        kek = self._get_kek(kek_meta_dto)
        unencrypted = encrypt_dto.unencrypted
        if not isinstance(unencrypted, bytes):
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
        byte_length = int(generate_dto.bit_length) // 8
        unencrypted = os.urandom(byte_length)

        return self.encrypt(c.EncryptDTO(unencrypted),
                            kek_meta_dto,
                            project_id)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, project_id):
        """Generate asymmetric keys based on below rules:

        - RSA, with passphrase (supported)
        - RSA, without passphrase (supported)
        - DSA, without passphrase (supported)
        - DSA, with passphrase (supported)
        """
        if(generate_dto.algorithm is None or generate_dto
                .algorithm.lower() == 'rsa'):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=generate_dto.bit_length,
                backend=default_backend()
            )
        elif generate_dto.algorithm.lower() == 'dsa':
            private_key = dsa.generate_private_key(
                key_size=generate_dto.bit_length,
                backend=default_backend()
            )
        else:
            raise c.CryptoPrivateKeyFailureException()

        public_key = private_key.public_key()

        if generate_dto.algorithm.lower() == 'rsa':
            private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=self._get_encryption_algorithm(
                    generate_dto.passphrase)
            )

            public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        if generate_dto.algorithm.lower() == 'dsa':
            private_key = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=self._get_encryption_algorithm(
                    generate_dto.passphrase)
            )
            public_key = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        private_dto = self.encrypt(c.EncryptDTO(private_key),
                                   kek_meta_dto,
                                   project_id)

        public_dto = self.encrypt(c.EncryptDTO(public_key),
                                  kek_meta_dto,
                                  project_id)

        passphrase_dto = None
        if generate_dto.passphrase:
            if isinstance(generate_dto.passphrase, str):
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
        elif type_enum == c.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length,
                                                mode)
        elif type_enum == c.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION:
            return self._is_algorithm_supported(algorithm,
                                                bit_length,
                                                mode)
        else:
            return False

    def _get_encryption_algorithm(self, passphrase):
        """Choose whether to use encryption or not based on passphrase

        serialization.BestAvailableEncryption fails if passphrase is not
        given or if less than one byte therefore we need to check if it is
        valid or not
        """
        if passphrase:
            # encryption requires password in bytes format
            algorithm = serialization.BestAvailableEncryption(
                # default encoding is utf-8
                encodeutils.safe_encode(passphrase)
            )
        else:
            algorithm = serialization.NoEncryption()

        return algorithm

    def _is_algorithm_supported(self, algorithm=None,
                                bit_length=None, mode=None):
        """check if algorithm and bit_length combination is supported."""
        if algorithm is None or bit_length is None:
            return False

        length_factor = 1

        # xts-mode cuts the effective key for the algorithm in half,
        # so the bit_length must be the double of the supported length.
        # in the future there should be a validation of supported modes too.
        if mode is not None and mode.lower() == "xts":
            length_factor = 2

        if (algorithm.lower() in c.PluginSupportTypes.SYMMETRIC_ALGORITHMS
            and bit_length / length_factor
                in c.PluginSupportTypes.SYMMETRIC_KEY_LENGTHS):
            return True
        elif (algorithm.lower() in c.PluginSupportTypes.ASYMMETRIC_ALGORITHMS
              and bit_length in c.PluginSupportTypes.ASYMMETRIC_KEY_LENGTHS):
            return True
        else:
            return False
