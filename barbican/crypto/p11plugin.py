# TODO: Restore this: import PyKCS11
#       This code is disabled just enough to pass tox tests, but once full
#       integration into Barbican is achieved, this code should re-enabled.

import base64

from oslo.config import cfg

from barbican.common import exception
from barbican.crypto.plugin import CryptoPluginBase

from barbican.openstack.common import jsonutils as json
from barbican.openstack.common.gettextutils import _


# TODO: Remove this:
PyKCS11 = {}

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


class P11CryptoPlugin(CryptoPluginBase):
    """
    PKCS11 supporting implementation of the crypto plugin.
    Generates a key per tenant and encrypts using AES-256-CBC.
    This implementation currently relies on an unreleased fork of PyKCS11.
    """

    def __init__(self, conf=cfg.CONF, library=None):
        self.block_size = 16  # in bytes
        self.kek_key_length = 32  # in bytes (256-bit)
        self.algorithm = 0x8000011c  # CKM_AES_GCM vendor prefixed.
        if library is not None:
            self.pkcs11 = library
        else:
            self.pkcs11 = PyKCS11.PyKCS11Lib()
        if conf.p11_crypto_plugin.library_path is None:
            raise ValueError(_("library_path is required"))
        else:
            self.pkcs11.load(conf.p11_crypto_plugin.library_path)
        # initialize the library. PyKCS11 does not supply this for free
        self._check_error(self.pkcs11.lib.C_Initialize())
         # TODO: check if session stays open/reopen when closed
        self.session = self.pkcs11.openSession(1)
        self.session.login(conf.p11_crypto_plugin.login)
        self.rw_session = self.pkcs11.openSession(1, PyKCS11.CKF_RW_SESSION)
        self.rw_session.login(conf.p11_crypto_plugin.login)

    def _pad(self, unencrypted):
        """Adds padding to unencrypted byte string."""
        pad_length = self.block_size - (len(unencrypted) % self.block_size)
        return unencrypted + (chr(pad_length) * pad_length)

    def _strip_pad(self, unencrypted):
        pad_length = ord(unencrypted[-1:])
        unpadded = unencrypted[:-pad_length]
        return unpadded

    def _check_error(self, value):
        if value != PyKCS11.CKR_OK:
            # TODO: probably shouldn't raise PyKCS11 error here
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
        elif len(keys) > 1:
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

    def encrypt(self, unencrypted, kek_meta_tenant, tenant):
        # TODO: GCM should not require padding.
        padded_data = self._pad(unencrypted)
        key = self._get_key_by_label(kek_meta_tenant.kek_label)
        iv = self.generate_iv()
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        encrypted = self.session.encrypt(key, padded_data, mech)
        cyphertext = b''.join(chr(i) for i in encrypted)
        kek_meta_extended = json.dumps({
            'iv': base64.b64encode(iv)
        })

        return cyphertext, kek_meta_extended

    def decrypt(self, encrypted, kek_meta_tenant, kek_meta_extended, tenant):
        key = self._get_key_by_label(kek_meta_tenant.kek_label)
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        gcm = self._build_gcm_params(iv)
        mech = PyKCS11.Mechanism(self.algorithm, gcm)
        decrypted = self.session.decrypt(key, encrypted, mech)
        padded_secret = b''.join(chr(i) for i in decrypted)
        return self._strip_pad(padded_secret)

    def bind_kek_metadata(self, kek_metadata):
        # Enforce idempotency: If we've already generated a key for the
        # kek_label, leave now.
        key = self._get_key_by_label(kek_metadata.kek_label)
        if key:
            return

        # To be persisted by Barbican:
        kek_metadata.algorithm = 'AES'
        kek_metadata.bit_length = self.kek_key_length * 8
        kek_metadata.mode = 'GCM'
        kek_metadata.plugin_meta = None

        # Generate the key.
        # TODO: review template to ensure it's what we want
        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, self.kek_key_length),
            (PyKCS11.CKA_LABEL, kek_metadata.kek_label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_WRAP, True),
            (PyKCS11.CKA_UNWRAP, True),
            (PyKCS11.CKA_EXTRACTABLE, False))
        ckattr = self.session._template2ckattrlist(template)

        m = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
        key = PyKCS11.CK_OBJECT_HANDLE()
        self._check_error(
            self.pkcs11.lib.C_GenerateKey(
                self.rw_session.session,
                m,
                ckattr,
                key
            )
        )

    def create(self, algorithm, bit_length):
        if bit_length % 8 != 0:
            raise ValueError('Bit lengths must be divisible by 8')
        byte_length = bit_length / 8
        rand = self.session.generateRandom(byte_length)
        if len(rand) != byte_length:
            raise P11CryptoPluginException()
        return rand

    def supports(self, secret_type):
        return True
