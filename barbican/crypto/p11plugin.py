import PyKCS11
import uuid

from oslo.config import cfg

from barbican.common import exception
from barbican.crypto.plugin import CryptoPluginBase

from barbican.openstack.common import jsonutils as json
from barbican.openstack.common.gettextutils import _


class P11CryptoPluginException(exception.BarbicanException):
    message = _("TODO")  # TODO


class P11CryptoPlugin(CryptoPluginBase):
    """
    PKCS11 supporting implementation of the crypto plugin.
    Generates a key per tenant and encrypts using AES-256-CBC.
    This implementation currently relies on an unreleased fork of PyKCS11.
    """

    def __init__(self, conf=cfg.CONF):
        self.block_size = 16
        self.kek_key_length = 32
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        # TODO check if conf crypto path is none
        #self.pkcs11.load(conf.crypto.p11_crypto_plugin_lib_path)
        self.pkcs11.load('/usr/lib/libCryptoki2_64.so')  # TODO: load from conf
        # initialize the library. PyKCS11 does not supply this for free
        self._check_error(self.pkcs11.lib.C_Initialize())
         # TODO: check if session stays open/reopen when closed
        self.session = self.pkcs11.openSession(1)
        self.rw_session = self.pkcs11.openSession(1, PyKCS11.CKF_RW_SESSION)

    def _pad(self, unencrypted):
        """Adds padding to unencrypted byte string."""
        pad_length = self.block_size - (
            len(unencrypted) % self.block_size
        )
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
            raise P11CryptoPluginException()  # TODO:make this a mega exception

    def _get_current_key_label_for_tenant(self, tenant):
        key_label = self.repo.get_key(tenant)  # TODO
        return key_label

    def _generate_key_for_tenant(self, tenant):
        # TODO: uuid generation from sufficient entropy?
        key_label = "tenant-{0}-key-{1}".format(tenant.tenant_id, uuid.uuid4())
        template = (
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, self.kek_key_length),
            (PyKCS11.CKA_LABEL, key_label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_DECRYPT, True),
            #(PyKCS11.CKA_TOKEN, True), # TODO: enable this (saves to HSM)
            (PyKCS11.CKA_WRAP, True),
            (PyKCS11.CKA_UNWRAP, True),
            # TODO: make these unextractable if feasible
            (PyKCS11.CKA_EXTRACTABLE, True))
        ckattr = self.session._template2ckattrlist(template)

        m = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
        key = PyKCS11.CK_OBJECT_HANDLE()
        self._check_error(
            self.pkcs11.lib.C_GenerateKey(self.session.session, m, ckattr, key)
        )
        self.repo.write_key(key_label, tenant)  # TODO: write key
        return (key, key_label)

    def _build_kek_metadata(self, mechanism, key_label, iv):
        # TODO: CBC, default (exception?)
        encryption_type = {
            PyKCS11.CKM_AES_ECB: 'AES ECB',
            PyKCS11.CKM_AES_CBC_PAD: 'AES CBC PAD',
            # TODO: determine if PKCS11 GCM pads automatically
            PyKCS11.CKM_AES_GCM: 'AES GCM'
        }[mechanism.mechanism]

        kek_metadata = json.dumps({
            'plugin': 'P11CryptoPlugin',
            'encryption': encryption_type,
            'kek_length': self.kek_key_length,
            'kek': key_label
        })
        return kek_metadata

    def encrypt(self, unencrypted, tenant):
        padded_data = self._pad(unencrypted)

        key_label = self._get_current_key_label_for_tenant(tenant)
        if key_label:
            key = self._get_key_by_label(key_label)
        else:
            key, key_label = self._generate_key_for_tenant(tenant)

        iv = self.session.generateRandom(self.block_size)
        mech = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC_PAD, iv)
        encrypted = self.session.encrypt(key, padded_data, mech)
        cyphertext = b''.join(chr(i) for i in encrypted)

        kek_metadata = self._build_kek_metadata(mech, key_label, iv)

        return cyphertext, kek_metadata

    def decrypt(self, encrypted, kek_metadata, tenant):
        kek_info = json.loads(kek_metadata)
        key, iv = self._get_key_by_label(kek_info['kek'])  # TODO: get IV
        mech = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC_PAD, iv)
        decrypted = self.session.decrypt(key, encrypted, mech)
        padded_secret = b''.join(chr(i) for i in decrypted)
        return self._strip_pad(padded_secret)

    def create(self, algorithm, bit_length):
        if bit_length % 8 != 0:
            raise ValueError('Bit lengths must be divisible by 8')
        byte_length = bit_length / 8
        rand = self.session.generateRandom(byte_length)
        if len(rand) != byte_length:
            raise P11CryptoPluginException()  # TODO: revisit exceptions
        return rand

    def supports(self, secret_type):
        return True
