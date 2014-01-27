try:
    import PyKCS11
except ImportError:
    PyKCS11 = {}  # TODO: remove testing workaround


import base64

from oslo.config import cfg

from barbican.common import exception
from barbican.crypto import plugin

from barbican.openstack.common import jsonutils as json
from barbican.openstack.common.gettextutils import _


CONF = cfg.CONF

p11_crypto_plugin_group = cfg.OptGroup(name='p11_crypto_plugin',
                                       title="PKCS11 Crypto Plugin Options")
p11_crypto_plugin_opts = [
    cfg.StrOpt('library_path',
               default=None,
               help=_('Path to vendor PKCS11 library')),
    cfg.StrOpt('login',
               default=None,
               help=_('Password to login to PKCS11 session'))
]
CONF.register_group(p11_crypto_plugin_group)
CONF.register_opts(p11_crypto_plugin_opts, group=p11_crypto_plugin_group)


class P11CryptoPluginKeyException(exception.BarbicanException):
    message = _("More than one key found for label")


class P11CryptoPluginException(exception.BarbicanException):
    message = _("General exception")


class P11CryptoPlugin(plugin.CryptoPluginBase):
    """
    PKCS11 supporting implementation of the crypto plugin.
    Generates a key per tenant and encrypts using AES-256-GCM.
    This implementation currently relies on an unreleased fork of PyKCS11.
    """

    def __init__(self, conf=cfg.CONF):
        self.block_size = 16  # in bytes
        self.kek_key_length = 32  # in bytes (256-bit)
        self.algorithm = 0x8000011c  # CKM_AES_GCM vendor prefixed.
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        if conf.p11_crypto_plugin.library_path is None:
            raise ValueError(_("library_path is required"))
        else:
            self.pkcs11.load(conf.p11_crypto_plugin.library_path)
        # initialize the library. PyKCS11 does not supply this for free
        self._check_error(self.pkcs11.lib.C_Initialize())
        self.session = self.pkcs11.openSession(1)
        self.session.login(conf.p11_crypto_plugin.login)
        self.rw_session = self.pkcs11.openSession(1, PyKCS11.CKF_RW_SESSION)
        self.rw_session.login(conf.p11_crypto_plugin.login)

    def _check_error(self, value):
        if value != PyKCS11.CKR_OK:
            raise PyKCS11.PyKCS11Error(value)

    def _get_key_by_label(self, key_label):
        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_LABEL, key_label))
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

    def _generate_kek(self, kek_label):
        # TODO: review template to ensure it's what we want
        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, self.kek_key_length),
            (PyKCS11.CKA_LABEL, kek_label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_WRAP, True),
            (PyKCS11.CKA_UNWRAP, True),
            (PyKCS11.CKA_EXTRACTABLE, False))
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

    def encrypt(self, unencrypted, kek_meta_dto, keystone_id):
        key = self._get_key_by_label(kek_meta_dto.kek_label)
        iv = self._generate_iv()
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        encrypted = self.session.encrypt(key, unencrypted, mech)
        cyphertext = b''.join(chr(i) for i in encrypted)
        kek_meta_extended = json.dumps({
            'iv': base64.b64encode(iv)
        })

        return cyphertext, kek_meta_extended

    def decrypt(self, encrypted, kek_meta_dto, kek_meta_extended, keystone_id):
        key = self._get_key_by_label(kek_meta_dto.kek_label)
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        decrypted = self.session.decrypt(key, encrypted, mech)
        secret = b''.join(chr(i) for i in decrypted)
        return secret

    def bind_kek_metadata(self, kek_meta_dto):
        # Enforce idempotency: If we've already generated a key for the
        # kek_label, leave now.
        key = self._get_key_by_label(kek_meta_dto.kek_label)
        if not key:
            self._generate_kek(kek_meta_dto.kek_label)
            # To be persisted by Barbican:
            kek_meta_dto.algorithm = 'AES'
            kek_meta_dto.bit_length = self.kek_key_length * 8
            kek_meta_dto.mode = 'GCM'
            kek_meta_dto.plugin_meta = None

        return kek_meta_dto

    def create(self, bit_length, type_enum, algorithm=None, mode=None):
        byte_length = bit_length / 8
        rand = self.session.generateRandom(byte_length)
        if len(rand) != byte_length:
            raise P11CryptoPluginException()
        return rand

    def supports(self, type_enum, algorithm=None, mode=None):
        if type_enum == plugin.PluginSupportTypes.ENCRYPT_DECRYPT:
            return True
        elif type_enum == plugin.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return True
        else:
            return False
