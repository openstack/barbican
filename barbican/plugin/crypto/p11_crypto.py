#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

try:
    import PyKCS11
except ImportError:
    PyKCS11 = {}  # TODO(reaperhulk): remove testing workaround


import base64

from oslo.config import cfg

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.openstack.common import jsonutils as json
from barbican.plugin.crypto import crypto as plugin


CONF = cfg.CONF
LOG = utils.getLogger(__name__)

p11_crypto_plugin_group = cfg.OptGroup(name='p11_crypto_plugin',
                                       title="PKCS11 Crypto Plugin Options")
p11_crypto_plugin_opts = [
    cfg.StrOpt('library_path',
               help=u._('Path to vendor PKCS11 library')),
    cfg.StrOpt('login',
               help=u._('Password to login to PKCS11 session')),
    cfg.StrOpt('mkek_label',
               help=u._('Master KEK label (used in the HSM)')),
    cfg.IntOpt('mkek_length',
               help=u._('Master KEK length in bytes.')),
    cfg.StrOpt('hmac_label',
               help=u._('HMAC label (used in the HSM)')),
]
CONF.register_group(p11_crypto_plugin_group)
CONF.register_opts(p11_crypto_plugin_opts, group=p11_crypto_plugin_group)


class P11CryptoPluginKeyException(exception.BarbicanException):
    message = u._("More than one key found for label")


class P11CryptoPluginException(exception.BarbicanException):
    message = u._("General exception")


class P11CryptoPlugin(plugin.CryptoPluginBase):
    """PKCS11 supporting implementation of the crypto plugin.

    Generates a single master key and a single HMAC key that remain in the
    HSM, then generates a key per project in the HSM, wraps the key, computes
    an HMAC, and stores it in the DB. The project key is never unencrypted
    outside the HSM.

    This implementation currently relies on an unreleased fork of PyKCS11.
    """

    def __init__(self, conf=cfg.CONF):
        self.block_size = 16  # in bytes
        self.algorithm = 0x8000011c  # CKM_AES_GCM vendor prefixed.
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        if conf.p11_crypto_plugin.library_path is None:
            raise ValueError(u._("library_path is required"))
        else:
            self.pkcs11.load(conf.p11_crypto_plugin.library_path)
        # initialize the library. PyKCS11 does not supply this for free
        self._check_error(self.pkcs11.lib.C_Initialize())
        self.session = self.pkcs11.openSession(1)
        self.session.login(conf.p11_crypto_plugin.login)
        self.rw_session = self.pkcs11.openSession(1, PyKCS11.CKF_RW_SESSION)
        self.rw_session.login(conf.p11_crypto_plugin.login)
        self.current_mkek_label = conf.p11_crypto_plugin.mkek_label
        self.current_hmac_label = conf.p11_crypto_plugin.hmac_label
        LOG.debug("Current mkek label: %s", self.current_mkek_label)
        LOG.debug("Current hmac label: %s", self.current_hmac_label)
        self.key_handles = {}
        # cache current MKEK handle in the dictionary
        self._get_or_generate_mkek(
            self.current_mkek_label,
            conf.p11_crypto_plugin.mkek_length
        )
        self._get_or_generate_hmac_key(self.current_hmac_label)

    def _check_error(self, value):
        if value != PyKCS11.CKR_OK:
            raise PyKCS11.PyKCS11Error(value)

    def _get_or_generate_mkek(self, mkek_label, mkek_key_length):
        mkek = self._get_key_handle(mkek_label)
        if not mkek:
            # Generate a key that is persistent and not extractable
            template = (
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
                (PyKCS11.CKA_VALUE_LEN, mkek_key_length),
                (PyKCS11.CKA_LABEL, mkek_label),
                (PyKCS11.CKA_PRIVATE, True),
                (PyKCS11.CKA_SENSITIVE, True),
                (PyKCS11.CKA_ENCRYPT, True),
                (PyKCS11.CKA_DECRYPT, True),
                (PyKCS11.CKA_SIGN, True),
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_WRAP, True),
                (PyKCS11.CKA_UNWRAP, True),
                (PyKCS11.CKA_EXTRACTABLE, False))
            mkek = self._generate_kek(template)

        self.key_handles[mkek_label] = mkek

        return mkek

    def _get_or_generate_hmac_key(self, hmac_label):
        hmac_key = self._get_key_handle(hmac_label)
        if not hmac_key:
            # Generate a key that is persistent and not extractable
            template = (
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
                (PyKCS11.CKA_VALUE_LEN, 32),
                (PyKCS11.CKA_LABEL, hmac_label),
                (PyKCS11.CKA_PRIVATE, True),
                (PyKCS11.CKA_SENSITIVE, True),
                (PyKCS11.CKA_SIGN, True),
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_EXTRACTABLE, False))
            hmac_key = self._generate_kek(template)

        self.key_handles[hmac_label] = hmac_key

        return hmac_key

    def _get_key_handle(self, mkek_label):
        if mkek_label in self.key_handles:
            return self.key_handles[mkek_label]

        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_LABEL, mkek_label))
        keys = self.session.findObjects(template)
        if len(keys) == 1:
            return keys[0]
        elif len(keys) == 0:
            return None
        else:
            raise P11CryptoPluginKeyException()

    def _generate_iv(self):
        iv = self.session.generateRandom(self.block_size)
        iv = b''.join(chr(i) for i in iv)
        if len(iv) != self.block_size:
            raise P11CryptoPluginException()
        return iv

    def _build_gcm_params(self, iv):
        gcm = PyKCS11.LowLevel.CK_AES_GCM_PARAMS()
        gcm.pIv = iv
        gcm.ulIvLen = len(iv)
        gcm.ulIvBits = len(iv) * 8
        gcm.ulTagBits = 128
        return gcm

    def _generate_kek(self, template):
        """Generates both master and project KEKs

        :param template: A tuple of tuples in (CKA_TYPE, VALUE) form
        """
        ckattr = self.session._template2ckattrlist(template)

        m = PyKCS11.LowLevel.CK_MECHANISM()
        m.mechanism = PyKCS11.LowLevel.CKM_AES_KEY_GEN

        key = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        self._check_error(
            self.pkcs11.lib.C_GenerateKey(
                self.rw_session.session,
                m,
                ckattr,
                key
            )
        )
        return key

    def _generate_wrapped_kek(self, kek_label, key_length):
        # generate a non-persistent key that is extractable
        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, key_length),
            (PyKCS11.CKA_LABEL, kek_label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_TOKEN, False),  # not persistent
            (PyKCS11.CKA_WRAP, True),
            (PyKCS11.CKA_UNWRAP, True),
            (PyKCS11.CKA_EXTRACTABLE, True))  # extractable
        kek = self._generate_kek(template)
        m = PyKCS11.LowLevel.CK_MECHANISM()
        m.mechanism = PyKCS11.LowLevel.CKM_AES_CBC_PAD
        iv = self._generate_iv()
        m.pParameter = iv
        encrypted = PyKCS11.ckbytelist()
        mkek = self.key_handles[self.current_mkek_label]
        # first call reserves the bytes required in the ckbytelist
        self._check_error(
            self.pkcs11.lib.C_WrapKey(
                self.rw_session.session, m, mkek, kek, encrypted
            )
        )
        # second call wraps and stores to encrypted
        self._check_error(
            self.pkcs11.lib.C_WrapKey(
                self.rw_session.session, m, mkek, kek, encrypted
            )
        )
        wrapped_key = b''.join(chr(i) for i in encrypted)
        hmac = self._compute_hmac(encrypted)
        return {
            'iv': base64.b64encode(iv),
            'wrapped_key': base64.b64encode(wrapped_key),
            'hmac': base64.b64encode(hmac),
            'mkek_label': self.current_mkek_label,
            'hmac_label': self.current_hmac_label
        }

    def _compute_hmac(self, wrapped_bytelist):
        m = PyKCS11.LowLevel.CK_MECHANISM()
        m.mechanism = PyKCS11.LowLevel.CKM_SHA256_HMAC
        hmac_bytelist = PyKCS11.ckbytelist()
        hmac_key = self.key_handles[self.current_hmac_label]
        self._check_error(
            self.pkcs11.lib.C_SignInit(self.rw_session.session, m, hmac_key)
        )

        # first call reserves the bytes required in the ckbytelist
        self._check_error(
            self.pkcs11.lib.C_Sign(
                self.rw_session.session, wrapped_bytelist, hmac_bytelist
            )
        )
        # second call computes HMAC
        self._check_error(
            self.pkcs11.lib.C_Sign(
                self.rw_session.session, wrapped_bytelist, hmac_bytelist
            )
        )
        return b''.join(chr(i) for i in hmac_bytelist)

    def _verify_hmac(self, hmac_key, hmac_bytelist, wrapped_bytelist):
        m = PyKCS11.LowLevel.CK_MECHANISM()
        m.mechanism = PyKCS11.LowLevel.CKM_SHA256_HMAC
        self._check_error(
            self.pkcs11.lib.C_VerifyInit(self.rw_session.session, m, hmac_key)
        )
        self._check_error(
            self.pkcs11.lib.C_Verify(
                self.rw_session.session, wrapped_bytelist, hmac_bytelist
            )
        )

    def _unwrap_key(self, plugin_meta):
        """Unwraps byte string to key handle in HSM.

        :param plugin_meta: kek_meta_dto plugin meta (json string)
        :returns: Key handle from HSM. No unencrypted bytes.
        """
        meta = json.loads(plugin_meta)
        iv = base64.b64decode(meta['iv'])
        hmac = base64.b64decode(meta['hmac'])
        wrapped_key = base64.b64decode(meta['wrapped_key'])
        mkek = self._get_key_handle(meta['mkek_label'])
        hmac_key = self._get_key_handle(meta['hmac_label'])
        LOG.debug("Unwrapping key with %s mkek label", meta['mkek_label'])

        hmac_bytelist = PyKCS11.ckbytelist()
        hmac_bytelist.reserve(len(hmac))
        for x in hmac:
            hmac_bytelist.append(ord(x))
        wrapped_bytelist = PyKCS11.ckbytelist()
        wrapped_bytelist.reserve(len(wrapped_key))
        for x in wrapped_key:
            wrapped_bytelist.append(ord(x))

        LOG.debug("Verifying key with %s hmac label", meta['hmac_label'])
        self._verify_hmac(hmac_key, hmac_bytelist, wrapped_bytelist)

        unwrapped = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        m = PyKCS11.LowLevel.CK_MECHANISM()
        m.mechanism = PyKCS11.LowLevel.CKM_AES_CBC_PAD
        m.pParameter = iv

        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_TOKEN, False),
            (PyKCS11.CKA_WRAP, True),
            (PyKCS11.CKA_UNWRAP, True),
            (PyKCS11.CKA_EXTRACTABLE, True)
        )
        ckattr = self.session._template2ckattrlist(template)

        self._check_error(
            self.pkcs11.lib.C_UnwrapKey(
                self.rw_session.session,
                m,
                mkek,
                wrapped_bytelist,
                ckattr,
                unwrapped
            )
        )

        return unwrapped

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        key = self._unwrap_key(kek_meta_dto.plugin_meta)
        iv = self._generate_iv()
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        encrypted = self.session.encrypt(key, encrypt_dto.unencrypted, mech)
        cyphertext = b''.join(chr(i) for i in encrypted)
        kek_meta_extended = json.dumps({
            'iv': base64.b64encode(iv)
        })

        return plugin.ResponseDTO(cyphertext, kek_meta_extended)

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        key = self._unwrap_key(kek_meta_dto.plugin_meta)
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        decrypted = self.session.decrypt(key, decrypt_dto.encrypted, mech)
        secret = b''.join(chr(i) for i in decrypted)
        return secret

    def bind_kek_metadata(self, kek_meta_dto):
        # Enforce idempotency: If we've already generated a key leave now.
        if not kek_meta_dto.plugin_meta:
            kek_meta_dto.plugin_meta = json.dumps(
                self._generate_wrapped_kek(
                    kek_meta_dto.kek_label, 32
                )
            )
            # To be persisted by Barbican:
            kek_meta_dto.algorithm = 'AES'
            kek_meta_dto.bit_length = 32 * 8
            kek_meta_dto.mode = 'CBC'

        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        byte_length = generate_dto.bit_length / 8
        rand = self.session.generateRandom(byte_length)
        if len(rand) != byte_length:
            raise P11CryptoPluginException()
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
