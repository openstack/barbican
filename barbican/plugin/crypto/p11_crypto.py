# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import base64

from oslo_config import cfg
from oslo_serialization import jsonutils as json

from barbican.common import config
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin.crypto import crypto as plugin
from barbican.plugin.crypto import pkcs11

CONF = config.new_config()
LOG = utils.getLogger(__name__)

p11_crypto_plugin_group = cfg.OptGroup(name='p11_crypto_plugin',
                                       title="PKCS11 Crypto Plugin Options")
p11_crypto_plugin_opts = [
    cfg.StrOpt('library_path',
               help=u._('Path to vendor PKCS11 library')),
    cfg.StrOpt('login',
               help=u._('Password to login to PKCS11 session'),
               secret=True),
    cfg.StrOpt('mkek_label',
               help=u._('Master KEK label (used in the HSM)')),
    cfg.IntOpt('mkek_length',
               help=u._('Master KEK length in bytes.')),
    cfg.StrOpt('hmac_label',
               help=u._('HMAC label (used in the HSM)')),
    cfg.IntOpt('slot_id',
               help=u._('HSM Slot ID'),
               default=1),
]
CONF.register_group(p11_crypto_plugin_group)
CONF.register_opts(p11_crypto_plugin_opts, group=p11_crypto_plugin_group)
config.parse_args(CONF)


class P11CryptoPlugin(plugin.CryptoPluginBase):
    """PKCS11 supporting implementation of the crypto plugin.

    Generates a single master key and a single HMAC key that remain in the
    HSM, then generates a key per project in the HSM, wraps the key, computes
    an HMAC, and stores it in the DB. The project key is never unencrypted
    outside the HSM.
    """

    def __init__(self, conf=CONF, ffi=None):
        self.conf = conf
        if conf.p11_crypto_plugin.library_path is None:
            raise ValueError(u._("library_path is required"))
        self.pkcs11 = pkcs11.PKCS11(
            library_path=conf.p11_crypto_plugin.library_path,
            login_passphrase=conf.p11_crypto_plugin.login,
            slot_id=conf.p11_crypto_plugin.slot_id,
            ffi=ffi
        )
        self.pkcs11.cache_mkek_and_hmac(conf.p11_crypto_plugin.mkek_label,
                                        conf.p11_crypto_plugin.hmac_label)

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        session = self.pkcs11.create_working_session()

        meta = json.loads(kek_meta_dto.plugin_meta)
        key = self.pkcs11.unwrap_key(
            meta['iv'], meta['hmac'], meta['wrapped_key'],
            meta['mkek_label'], meta['hmac_label'], session
        )
        iv = self.pkcs11.generate_random(16, session)
        ck_mechanism = self.pkcs11.build_gcm_mech(iv)

        rv = self.pkcs11.lib.C_EncryptInit(session, ck_mechanism.mech, key)
        self.pkcs11.check_error(rv)
        # GCM does not require padding, but sometimes HSMs don't seem to
        # know that and then you need to pad things for no reason.
        pt_padded = self.pkcs11.pad(encrypt_dto.unencrypted)
        pt_len = len(pt_padded)
        # The GCM mechanism adds a 16 byte tag to the front of the
        # cyphertext (which is the same length as the (annoyingly) padded
        # plaintext) so adding 16 bytes guarantees sufficient space.
        ct_len = self.pkcs11.ffi.new("CK_ULONG *", pt_len + 16)
        ct = self.pkcs11.ffi.new("CK_BYTE[{0}]".format(pt_len + 16))
        rv = self.pkcs11.lib.C_Encrypt(session, pt_padded, pt_len, ct, ct_len)
        self.pkcs11.check_error(rv)

        cyphertext = self.pkcs11.ffi.buffer(ct, ct_len[0])[:]
        kek_meta_extended = json.dumps({
            'iv': base64.b64encode(self.pkcs11.ffi.buffer(iv)[:])
        })

        self.pkcs11.close_session(session)

        return plugin.ResponseDTO(cyphertext, kek_meta_extended)

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        session = self.pkcs11.create_working_session()

        meta = json.loads(kek_meta_dto.plugin_meta)
        key = self.pkcs11.unwrap_key(
            meta['iv'], meta['hmac'], meta['wrapped_key'],
            meta['mkek_label'], meta['hmac_label'], session
        )
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        iv = self.pkcs11.ffi.new("CK_BYTE[]", iv)
        ck_mechanism = self.pkcs11.build_gcm_mech(iv)

        rv = self.pkcs11.lib.C_DecryptInit(session, ck_mechanism.mech, key)
        self.pkcs11.check_error(rv)
        pt = self.pkcs11.ffi.new(
            "CK_BYTE[{0}]".format(len(decrypt_dto.encrypted))
        )
        pt_len = self.pkcs11.ffi.new("CK_ULONG *", len(decrypt_dto.encrypted))
        rv = self.pkcs11.lib.C_Decrypt(
            session,
            decrypt_dto.encrypted,
            len(decrypt_dto.encrypted),
            pt,
            pt_len
        )
        self.pkcs11.check_error(rv)

        self.pkcs11.close_session(session)
        return self.pkcs11.unpad(self.pkcs11.ffi.buffer(pt, pt_len[0])[:])

    def bind_kek_metadata(self, kek_meta_dto):
        # Enforce idempotency: If we've already generated a key leave now.
        if not kek_meta_dto.plugin_meta:
            session = self.pkcs11.create_working_session()

            kek_length = 32
            kek_meta_dto.plugin_meta = json.dumps(
                self.pkcs11.generate_wrapped_kek(
                    kek_meta_dto.kek_label,
                    kek_length,
                    session
                )
            )
            # To be persisted by Barbican:
            kek_meta_dto.algorithm = 'AES'
            kek_meta_dto.bit_length = kek_length * 8
            kek_meta_dto.mode = 'CBC'

            # Clean up
            self.pkcs11.close_session(session)

        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        byte_length = generate_dto.bit_length / 8
        session = self.pkcs11.create_working_session()
        buf = self.pkcs11.generate_random(byte_length, session)
        self.pkcs11.close_session(session)
        rand = self.pkcs11.ffi.buffer(buf)[:]
        assert len(rand) == byte_length
        return self.encrypt(plugin.EncryptDTO(rand), kek_meta_dto, project_id)

    def generate_asymmetric(self, generate_dto, kek_meta_dto, project_id):
        raise NotImplementedError(u._("Feature not implemented for PKCS11"))

    def supports(self, type_enum, algorithm=None, bit_length=None, mode=None):
        if type_enum == plugin.PluginSupportTypes.ENCRYPT_DECRYPT:
            return True
        elif type_enum == plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return True
        elif type_enum == plugin.PluginSupportTypes.ASYMMETRIC_KEY_GENERATION:
            return False
        else:
            return False
