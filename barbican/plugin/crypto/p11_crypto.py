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

import base64
import collections
import textwrap

import cffi
from cryptography.hazmat.primitives import padding
from eventlet import semaphore
from oslo_config import cfg

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.openstack.common import jsonutils as json
from barbican.plugin.crypto import crypto as plugin


Attribute = collections.namedtuple("Attribute", ["type", "value"])

CKR_OK = 0
CKF_RW_SESSION = (1 << 1)
CKF_SERIAL_SESSION = (1 << 2)
CKU_SO = 0
CKU_USER = 1

CKO_SECRET_KEY = 4
CKK_AES = 0x1f

CKA_CLASS = 0
CKA_TOKEN = 1
CKA_PRIVATE = 2
CKA_LABEL = 3
CKA_APPLICATION = 0x10
CKA_VALUE = 0x11
CKA_OBJECT_ID = 0x12
CKA_CERTIFICATE_TYPE = 0x80
CKA_ISSUER = 0x81
CKA_SERIAL_NUMBER = 0x82
CKA_AC_ISSUER = 0x83
CKA_OWNER = 0x84
CKA_ATTR_TYPES = 0x85
CKA_TRUSTED = 0x86
CKA_CERTIFICATE_CATEGORY = 0x87
CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x88
CKA_URL = 0x89
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x8a
CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x8b
CKA_CHECK_VALUE = 0x90
CKA_KEY_TYPE = 0x100
CKA_SUBJECT = 0x101
CKA_ID = 0x102
CKA_SENSITIVE = 0x103
CKA_ENCRYPT = 0x104
CKA_DECRYPT = 0x105
CKA_WRAP = 0x106
CKA_UNWRAP = 0x107
CKA_SIGN = 0x108
CKA_SIGN_RECOVER = 0x109
CKA_VERIFY = 0x10a
CKA_VERIFY_RECOVER = 0x10b
CKA_DERIVE = 0x10c
CKA_START_DATE = 0x110
CKA_END_DATE = 0x111
CKA_MODULUS = 0x120
CKA_MODULUS_BITS = 0x121
CKA_PUBLIC_EXPONENT = 0x122
CKA_PRIVATE_EXPONENT = 0x123
CKA_PRIME_1 = 0x124
CKA_PRIME_2 = 0x125
CKA_EXPONENT_1 = 0x126
CKA_EXPONENT_2 = 0x127
CKA_COEFFICIENT = 0x128
CKA_PRIME = 0x130
CKA_SUBPRIME = 0x131
CKA_BASE = 0x132
CKA_PRIME_BITS = 0x133
CKA_SUB_PRIME_BITS = 0x134
CKA_VALUE_BITS = 0x160
CKA_VALUE_LEN = 0x161
CKA_EXTRACTABLE = 0x162
CKA_LOCAL = 0x163
CKA_NEVER_EXTRACTABLE = 0x164
CKA_ALWAYS_SENSITIVE = 0x165
CKA_KEY_GEN_MECHANISM = 0x166
CKA_MODIFIABLE = 0x170
CKA_ECDSA_PARAMS = 0x180
CKA_EC_PARAMS = 0x180
CKA_EC_POINT = 0x181
CKA_SECONDARY_AUTH = 0x200
CKA_AUTH_PIN_FLAGS = 0x201
CKA_ALWAYS_AUTHENTICATE = 0x202
CKA_WRAP_WITH_TRUSTED = 0x210
CKA_HW_FEATURE_TYPE = 0x300
CKA_RESET_ON_INIT = 0x301
CKA_HAS_RESET = 0x302
CKA_PIXEL_X = 0x400
CKA_PIXEL_Y = 0x401
CKA_RESOLUTION = 0x402
CKA_CHAR_ROWS = 0x403
CKA_CHAR_COLUMNS = 0x404
CKA_COLOR = 0x405
CKA_BITS_PER_PIXEL = 0x406
CKA_CHAR_SETS = 0x480
CKA_ENCODING_METHODS = 0x481
CKA_MIME_TYPES = 0x482
CKA_MECHANISM_TYPE = 0x500
CKA_REQUIRED_CMS_ATTRIBUTES = 0x501
CKA_DEFAULT_CMS_ATTRIBUTES = 0x502
CKA_SUPPORTED_CMS_ATTRIBUTES = 0x503


CKM_SHA256_HMAC = 0x251
CKM_AES_KEY_GEN = 0x1080
CKM_AES_CBC_PAD = 0x1085
CKM_AES_KEY_WRAP = 0x1090
VENDOR_SAFENET_CKM_AES_GCM = 0x8000011c

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


def _build_ffi():
    ffi = cffi.FFI()
    ffi.cdef(textwrap.dedent("""
    typedef unsigned char CK_BYTE;
    typedef unsigned long CK_ULONG;
    typedef unsigned long CK_RV;
    typedef unsigned long CK_SESSION_HANDLE;
    typedef unsigned long CK_OBJECT_HANDLE;
    typedef unsigned long CK_SLOT_ID;
    typedef unsigned long CK_FLAGS;
    typedef unsigned long CK_USER_TYPE;
    typedef unsigned char * CK_UTF8CHAR_PTR;
    typedef ... *CK_NOTIFY;

    typedef unsigned long ck_attribute_type_t;
    struct ck_attribute {
        ck_attribute_type_t type;
        void *value;
        unsigned long value_len;
    };
    typedef struct ck_attribute CK_ATTRIBUTE;
    typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

    typedef unsigned long ck_mechanism_type_t;
    struct ck_mechanism {
        ck_mechanism_type_t mechanism;
        void *parameter;
        unsigned long parameter_len;
    };
    typedef struct ck_mechanism CK_MECHANISM;
    typedef CK_MECHANISM *CK_MECHANISM_PTR;
    typedef CK_BYTE *CK_BYTE_PTR;
    typedef CK_ULONG *CK_ULONG_PTR;

    typedef struct CK_AES_GCM_PARAMS {
        char * pIv;
        unsigned long ulIvLen;
        unsigned long ulIvBits;
        char * pAAD;
        unsigned long ulAADLen;
        unsigned long ulTagBits;
    } CK_AES_GCM_PARAMS;
    """))
    # FUNCTIONS
    ffi.cdef(textwrap.dedent("""
    CK_RV C_Initialize(void *);
    CK_RV C_OpenSession(CK_SLOT_ID, CK_FLAGS, void *, CK_NOTIFY,
                        CK_SESSION_HANDLE *);
    CK_RV C_CloseSession(CK_SESSION_HANDLE);
    CK_RV C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR,
                  CK_ULONG);
    CK_RV C_FindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV C_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG,
                        CK_ULONG *);
    CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE);
    CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *,
                        CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                      CK_BYTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG,
                      CK_OBJECT_HANDLE *);
    CK_RV C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                    CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                        CK_OBJECT_HANDLE);
    CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                    CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                        CK_OBJECT_HANDLE);
    CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR);
    CK_RV C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                     CK_OBJECT_HANDLE);
    CK_RV C_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                 CK_ULONG_PTR);
    CK_RV C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                       CK_OBJECT_HANDLE);
    CK_RV C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                   CK_ULONG);
    CK_RV C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    """))
    return ffi


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
    """

    def __init__(self, conf=cfg.CONF, ffi=None):
        self.enc_sem = semaphore.Semaphore()
        self.dec_sem = semaphore.Semaphore()
        self.verify_sem = semaphore.Semaphore()
        self.block_size = 16  # in bytes
        # TODO(reaperhulk): abstract this so alternate algorithms/vendors
        # are possible.
        self.algorithm = VENDOR_SAFENET_CKM_AES_GCM
        if conf.p11_crypto_plugin.library_path is None:
            raise ValueError(u._("library_path is required"))
        self.ffi = _build_ffi() if not ffi else ffi
        self.lib = self.ffi.dlopen(conf.p11_crypto_plugin.library_path)

        self._check_error(self.lib.C_Initialize(self.ffi.NULL))

        self.session = self._open_session(1)
        self.rw_session = self._open_session(1)
        self._login(conf.p11_crypto_plugin.login, self.session)
        self._login(conf.p11_crypto_plugin.login, self.rw_session)

        self._perform_rng_self_test()

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

    def _perform_rng_self_test(self):
        test_random = self._generate_random(100)
        if self.ffi.buffer(test_random, 100)[:] == b"\x00" * 100:
            raise P11CryptoPluginException("Apparent RNG self-test failure.")

    def _open_session(self, slot):
        session_ptr = self.ffi.new("CK_SESSION_HANDLE *")
        rv = self.lib.C_OpenSession(
            slot,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            self.ffi.NULL,
            self.ffi.NULL,
            session_ptr
        )
        self._check_error(rv)
        session = session_ptr[0]
        return session

    def _login(self, password, session):
        rv = self.lib.C_Login(
            session,
            CKU_USER,
            password,
            len(password)
        )
        self._check_error(rv)

    def _check_error(self, value):
        if value != CKR_OK:
            raise P11CryptoPluginException(
                "HSM returned response code: {0}".format(value)
            )

    def _build_attributes(self, attrs):
        attributes = self.ffi.new("CK_ATTRIBUTE[{0}]".format(len(attrs)))
        val_list = []
        for index, attr in enumerate(attrs):
            attributes[index].type = attr.type
            if isinstance(attr.value, bool):
                if attr.value:
                    val_list.append(self.ffi.new("unsigned char *", 1))
                else:
                    val_list.append(self.ffi.new("unsigned char *", 0))

                attributes[index].value_len = 1  # sizeof(char) is 1
            elif isinstance(attr.value, int):
                # second because bools are also considered ints
                val_list.append(self.ffi.new("CK_ULONG *", attr.value))
                attributes[index].value_len = 8
            elif isinstance(attr.value, str):
                val_list.append(self.ffi.new("char []", attr.value))
                attributes[index].value_len = len(attr.value)
            else:
                raise TypeError("Unknown attribute type provided.")

            attributes[index].value = val_list[-1]

        return attributes, val_list

    def _get_or_generate_mkek(self, mkek_label, mkek_length):
        mkek = self._get_key_handle(mkek_label)
        if not mkek:
            # Generate a key that is persistent and not extractable
            template, val_list = self._build_attributes([
                Attribute(CKA_CLASS, CKO_SECRET_KEY),
                Attribute(CKA_KEY_TYPE, CKK_AES),
                Attribute(CKA_VALUE_LEN, mkek_length),
                Attribute(CKA_LABEL, mkek_label),
                Attribute(CKA_PRIVATE, True),
                Attribute(CKA_SENSITIVE, True),
                Attribute(CKA_ENCRYPT, True),
                Attribute(CKA_DECRYPT, True),
                Attribute(CKA_SIGN, True),
                Attribute(CKA_VERIFY, True),
                Attribute(CKA_TOKEN, True),
                Attribute(CKA_WRAP, True),
                Attribute(CKA_UNWRAP, True),
                Attribute(CKA_EXTRACTABLE, False)
            ])
            mkek = self._generate_kek(template)

        self.key_handles[mkek_label] = mkek

        return mkek

    def _get_or_generate_hmac_key(self, hmac_label):
        hmac_key = self._get_key_handle(hmac_label)
        if not hmac_key:
            # Generate a key that is persistent and not extractable
            template, val_list = self._build_attributes([
                Attribute(CKA_CLASS, CKO_SECRET_KEY),
                Attribute(CKA_KEY_TYPE, CKK_AES),
                Attribute(CKA_VALUE_LEN, 32),
                Attribute(CKA_LABEL, hmac_label),
                Attribute(CKA_PRIVATE, True),
                Attribute(CKA_SENSITIVE, True),
                Attribute(CKA_SIGN, True),
                Attribute(CKA_VERIFY, True),
                Attribute(CKA_TOKEN, True),
                Attribute(CKA_EXTRACTABLE, False)
            ])
            hmac_key = self._generate_kek(template)

        self.key_handles[hmac_label] = hmac_key

        return hmac_key

    def _get_key_handle(self, mkek_label):
        if mkek_label in self.key_handles:
            return self.key_handles[mkek_label]

        template, val_list = self._build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, CKK_AES),
            Attribute(CKA_LABEL, mkek_label)
        ])
        rv = self.lib.C_FindObjectsInit(
            self.session, template, len(template)
        )
        self._check_error(rv)

        returned_count = self.ffi.new("CK_ULONG *")
        object_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE *")
        rv = self.lib.C_FindObjects(
            self.session, object_handle_ptr, 2, returned_count
        )
        self._check_error(rv)
        if returned_count[0] == 1:
            key = object_handle_ptr[0]
        rv = self.lib.C_FindObjectsFinal(self.session)
        self._check_error(rv)
        if returned_count[0] == 1:
            return key
        elif returned_count[0] == 0:
            return None
        else:
            raise P11CryptoPluginKeyException()

    def _generate_random(self, length):
        buf = self.ffi.new("CK_BYTE[{0}]".format(length))
        rv = self.lib.C_GenerateRandom(self.session, buf, length)
        self._check_error(rv)
        return buf

    def _build_gcm_mech(self, iv):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.algorithm
        gcm = self.ffi.new("CK_AES_GCM_PARAMS *")
        gcm.pIv = iv
        gcm.ulIvLen = 16
        gcm.ulIvBits = 128
        gcm.ulTagBits = 128
        mech.parameter = gcm
        mech.parameter_len = 48  # sizeof(CK_AES_GCM_PARAMS)
        return mech

    def _generate_kek(self, template):
        """Generates both master and project KEKs

        :param template: A tuple of tuples in (CKA_TYPE, VALUE) form
        """
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_KEY_GEN
        object_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE *")
        rv = self.lib.C_GenerateKey(
            self.rw_session, mech, template, len(template), object_handle_ptr
        )

        self._check_error(rv)
        return object_handle_ptr[0]

    def _generate_wrapped_kek(self, kek_label, key_length):
        # generate a non-persistent key that is extractable
        template, val_list = self._build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, CKK_AES),
            Attribute(CKA_VALUE_LEN, key_length),
            Attribute(CKA_LABEL, kek_label),
            Attribute(CKA_PRIVATE, True),
            Attribute(CKA_SENSITIVE, True),
            Attribute(CKA_ENCRYPT, True),
            Attribute(CKA_DECRYPT, True),
            Attribute(CKA_TOKEN, False),  # not persistent
            Attribute(CKA_WRAP, True),
            Attribute(CKA_UNWRAP, True),
            Attribute(CKA_EXTRACTABLE, True)
        ])
        kek = self._generate_kek(template)
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_CBC_PAD
        iv = self._generate_random(16)
        mech.parameter = iv
        mech.parameter_len = 16
        mkek = self.key_handles[self.current_mkek_label]
        # Since we're using CKM_AES_CBC_PAD the maximum length of the
        # padded key will be the key length + one block. We allocate the
        # worst case scenario as a CK_BYTE array.
        padded_length = key_length + self.block_size

        buf = self.ffi.new("CK_BYTE[{0}]".format(padded_length))
        buf_len = self.ffi.new("CK_ULONG *", padded_length)
        rv = self.lib.C_WrapKey(self.rw_session, mech, mkek, kek, buf, buf_len)
        self._check_error(rv)
        wrapped_key = self.ffi.buffer(buf, buf_len[0])[:]
        hmac = self._compute_hmac(wrapped_key)
        return {
            'iv': base64.b64encode(self.ffi.buffer(iv)[:]),
            'wrapped_key': base64.b64encode(wrapped_key),
            'hmac': base64.b64encode(hmac),
            'mkek_label': self.current_mkek_label,
            'hmac_label': self.current_hmac_label
        }

    def _compute_hmac(self, wrapped_key):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_SHA256_HMAC
        hmac_key = self.key_handles[self.current_hmac_label]
        rv = self.lib.C_SignInit(self.rw_session, mech, hmac_key)
        self._check_error(rv)

        ck_bytes = self.ffi.new("CK_BYTE[]", wrapped_key)
        buf = self.ffi.new("CK_BYTE[32]")
        buf_len = self.ffi.new("CK_ULONG *", 32)
        rv = self.lib.C_Sign(
            self.rw_session, ck_bytes, len(wrapped_key), buf, buf_len
        )
        self._check_error(rv)
        return self.ffi.buffer(buf, buf_len[0])[:]

    def _verify_hmac(self, hmac_key, sig, wrapped_key):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_SHA256_HMAC
        with self.verify_sem:
            rv = self.lib.C_VerifyInit(self.rw_session, mech, hmac_key)
            self._check_error(rv)
            ck_bytes = self.ffi.new("CK_BYTE[]", wrapped_key)
            ck_sig = self.ffi.new("CK_BYTE[]", sig)
            rv = self.lib.C_Verify(
                self.rw_session, ck_bytes, len(wrapped_key), ck_sig, len(sig)
            )
            self._check_error(rv)

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

        LOG.debug("Verifying key with %s hmac label", meta['hmac_label'])
        self._verify_hmac(hmac_key, hmac, wrapped_key)

        unwrapped = self.ffi.new("CK_OBJECT_HANDLE *")
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_CBC_PAD
        iv = self.ffi.new("CK_BYTE[]", iv)
        mech.parameter = iv
        mech.parameter_len = 16

        template, val_list = self._build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, CKK_AES),
            Attribute(CKA_ENCRYPT, True),
            Attribute(CKA_DECRYPT, True),
            Attribute(CKA_TOKEN, False),
            Attribute(CKA_WRAP, True),
            Attribute(CKA_UNWRAP, True),
            Attribute(CKA_EXTRACTABLE, True)
        ])

        rv = self.lib.C_UnwrapKey(
            self.rw_session, mech, mkek, wrapped_key, len(wrapped_key),
            template, len(template), unwrapped
        )
        self._check_error(rv)

        return unwrapped[0]

    def _pad(self, unencrypted):
        padder = padding.PKCS7(self.block_size * 8).padder()
        return padder.update(unencrypted) + padder.finalize()

    def _unpad(self, unencrypted):
        unpadder = padding.PKCS7(self.block_size * 8).unpadder()
        return unpadder.update(unencrypted) + unpadder.finalize()

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        key = self._unwrap_key(kek_meta_dto.plugin_meta)
        iv = self._generate_random(16)
        mech = self._build_gcm_mech(iv)
        with self.enc_sem:
            rv = self.lib.C_EncryptInit(self.session, mech, key)
            self._check_error(rv)
            # GCM does not require padding, but sometimes HSMs don't seem to
            # know that and then you need to pad things for no reason.
            pt_padded = self._pad(encrypt_dto.unencrypted)
            pt_len = len(pt_padded)
            # The GCM mechanism adds a 16 byte tag to the front of the
            # cyphertext (which is the same length as the (annoyingly) padded
            # plaintext) so adding 16 bytes guarantees sufficient space.
            ct_len = self.ffi.new("CK_ULONG *", pt_len + 16)
            ct = self.ffi.new("CK_BYTE[{0}]".format(pt_len + 16))
            rv = self.lib.C_Encrypt(
                self.session, pt_padded, pt_len, ct, ct_len
            )
            self._check_error(rv)

        cyphertext = self.ffi.buffer(ct, ct_len[0])[:]
        kek_meta_extended = json.dumps({
            'iv': base64.b64encode(self.ffi.buffer(iv)[:])
        })

        return plugin.ResponseDTO(cyphertext, kek_meta_extended)

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        key = self._unwrap_key(kek_meta_dto.plugin_meta)
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        iv = self.ffi.new("CK_BYTE[]", iv)
        mech = self._build_gcm_mech(iv)
        with self.dec_sem:
            rv = self.lib.C_DecryptInit(self.session, mech, key)
            self._check_error(rv)
            pt = self.ffi.new(
                "CK_BYTE[{0}]".format(len(decrypt_dto.encrypted))
            )
            pt_len = self.ffi.new("CK_ULONG *", len(decrypt_dto.encrypted))
            rv = self.lib.C_Decrypt(
                self.session,
                decrypt_dto.encrypted,
                len(decrypt_dto.encrypted),
                pt,
                pt_len
            )
            self._check_error(rv)

        return self._unpad(self.ffi.buffer(pt, pt_len[0])[:])

    def bind_kek_metadata(self, kek_meta_dto):
        # Enforce idempotency: If we've already generated a key leave now.
        if not kek_meta_dto.plugin_meta:
            kek_length = 32
            kek_meta_dto.plugin_meta = json.dumps(
                self._generate_wrapped_kek(kek_meta_dto.kek_label, kek_length)
            )
            # To be persisted by Barbican:
            kek_meta_dto.algorithm = 'AES'
            kek_meta_dto.bit_length = kek_length * 8
            kek_meta_dto.mode = 'CBC'

        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        byte_length = generate_dto.bit_length / 8
        buf = self._generate_random(byte_length)
        rand = self.ffi.buffer(buf)[:]
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
