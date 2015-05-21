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
import collections
import textwrap

import cffi
from cryptography.hazmat.primitives import padding

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.openstack.common import jsonutils as json

LOG = utils.getLogger(__name__)

Attribute = collections.namedtuple("Attribute", ["type", "value"])
CKAttributes = collections.namedtuple("CKAttributes", ["template", "cffivals"])
CKMechanism = collections.namedtuple("CKMechanism", ["mech", "cffivals"])

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

ERROR_CODES = {
    1: 'CKR_CANCEL',
    2: 'CKR_HOST_MEMORY',
    3: 'CKR_SLOT_ID_INVALID',
    5: 'CKR_GENERAL_ERROR',
    6: 'CKR_FUNCTION_FAILED',
    7: 'CKR_ARGUMENTS_BAD',
    8: 'CKR_NO_EVENT',
    9: 'CKR_NEED_TO_CREATE_THREADS',
    0xa: 'CKR_CANT_LOCK',
    0x10: 'CKR_ATTRIBUTE_READ_ONLY',
    0x11: 'CKR_ATTRIBUTE_SENSITIVE',
    0x12: 'CKR_ATTRIBUTE_TYPE_INVALID',
    0x13: 'CKR_ATTRIBUTE_VALUE_INVALID',
    0x20: 'CKR_DATA_INVALID',
    0x21: 'CKR_DATA_LEN_RANGE',
    0x30: 'CKR_DEVICE_ERROR',
    0x31: 'CKR_DEVICE_MEMORY',
    0x32: 'CKR_DEVICE_REMOVED',
    0x40: 'CKR_ENCRYPTED_DATA_INVALID',
    0x41: 'CKR_ENCRYPTED_DATA_LEN_RANGE',
    0x50: 'CKR_FUNCTION_CANCELED',
    0x51: 'CKR_FUNCTION_NOT_PARALLEL',
    0x54: 'CKR_FUNCTION_NOT_SUPPORTED',
    0x60: 'CKR_KEY_HANDLE_INVALID',
    0x62: 'CKR_KEY_SIZE_RANGE',
    0x63: 'CKR_KEY_TYPE_INCONSISTENT',
    0x64: 'CKR_KEY_NOT_NEEDED',
    0x65: 'CKR_KEY_CHANGED',
    0x66: 'CKR_KEY_NEEDED',
    0x67: 'CKR_KEY_INDIGESTIBLE',
    0x68: 'CKR_KEY_FUNCTION_NOT_PERMITTED',
    0x69: 'CKR_KEY_NOT_WRAPPABLE',
    0x6a: 'CKR_KEY_UNEXTRACTABLE',
    0x70: 'CKR_MECHANISM_INVALID',
    0x71: 'CKR_MECHANISM_PARAM_INVALID',
    0x82: 'CKR_OBJECT_HANDLE_INVALID',
    0x90: 'CKR_OPERATION_ACTIVE',
    0x91: 'CKR_OPERATION_NOT_INITIALIZED',
    0xa0: 'CKR_PIN_INCORRECT',
    0xa1: 'CKR_PIN_INVALID',
    0xa2: 'CKR_PIN_LEN_RANGE',
    0xa3: 'CKR_PIN_EXPIRED',
    0xa4: 'CKR_PIN_LOCKED',
    0xb0: 'CKR_SESSION_CLOSED',
    0xb1: 'CKR_SESSION_COUNT',
    0xb3: 'CKR_SESSION_HANDLE_INVALID',
    0xb4: 'CKR_SESSION_PARALLEL_NOT_SUPPORTED',
    0xb5: 'CKR_SESSION_READ_ONLY',
    0xb6: 'CKR_SESSION_EXISTS',
    0xb7: 'CKR_SESSION_READ_ONLY_EXISTS',
    0xb8: 'CKR_SESSION_READ_WRITE_SO_EXISTS',
    0xc0: 'CKR_SIGNATURE_INVALID',
    0xc1: 'CKR_SIGNATURE_LEN_RANGE',
    0xd0: 'CKR_TEMPLATE_INCOMPLETE',
    0xd1: 'CKR_TEMPLATE_INCONSISTENT',
    0xe0: 'CKR_TOKEN_NOT_PRESENT',
    0xe1: 'CKR_TOKEN_NOT_RECOGNIZED',
    0xe2: 'CKR_TOKEN_WRITE_PROTECTED',
    0xf0: 'CKR_UNWRAPPING_KEY_HANDLE_INVALID',
    0xf1: 'CKR_UNWRAPPING_KEY_SIZE_RANGE',
    0xf2: 'CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT',
    0x100: 'CKR_USER_ALREADY_LOGGED_IN',
    0x101: 'CKR_USER_NOT_LOGGED_IN',
    0x102: 'CKR_USER_PIN_NOT_INITIALIZED',
    0x103: 'CKR_USER_TYPE_INVALID',
    0x104: 'CKR_USER_ANOTHER_ALREADY_LOGGED_IN',
    0x105: 'CKR_USER_TOO_MANY_TYPES',
    0x110: 'CKR_WRAPPED_KEY_INVALID',
    0x112: 'CKR_WRAPPED_KEY_LEN_RANGE',
    0x113: 'CKR_WRAPPING_KEY_HANDLE_INVALID',
    0x114: 'CKR_WRAPPING_KEY_SIZE_RANGE',
    0x115: 'CKR_WRAPPING_KEY_TYPE_INCONSISTENT',
    0x120: 'CKR_RANDOM_SEED_NOT_SUPPORTED',
    0x121: 'CKR_RANDOM_NO_RNG',
    0x130: 'CKR_DOMAIN_PARAMS_INVALID',
    0x150: 'CKR_BUFFER_TOO_SMALL',
    0x160: 'CKR_SAVED_STATE_INVALID',
    0x170: 'CKR_INFORMATION_SENSITIVE',
    0x180: 'CKR_STATE_UNSAVEABLE',
    0x190: 'CKR_CRYPTOKI_NOT_INITIALIZED',
    0x191: 'CKR_CRYPTOKI_ALREADY_INITIALIZED',
    0x1a0: 'CKR_MUTEX_BAD',
    0x1a1: 'CKR_MUTEX_NOT_LOCKED',
    0x200: 'CKR_FUNCTION_REJECTED',
    1 << 31: 'CKR_VENDOR_DEFINED'
}


def build_ffi():
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


class P11CryptoKeyHandleException(exception.BarbicanException):
    message = u._("No key handle was found")


class PKCS11(object):

    def __init__(self, library_path, mkek_label, mkek_length, hmac_label,
                 login_passphrase, slot_id, ffi=None):
        self.ffi = build_ffi() if not ffi else ffi
        self.lib = self.ffi.dlopen(library_path)

        # TODO(reaperhulk): abstract this so alternate algorithms/vendors
        # are possible.
        self.algorithm = VENDOR_SAFENET_CKM_AES_GCM
        self.block_size = 16  # in bytes
        self.key_handles = {}
        self.login_passphrase = login_passphrase
        self.slot_id = slot_id

        self.check_error(self.lib.C_Initialize(self.ffi.NULL))

        # Open session to perform self-test and get/generate mkek and hmac
        session = self.create_working_session()
        self.perform_rng_self_test(session)

        self.current_mkek_label = mkek_label
        self.current_hmac_label = hmac_label
        LOG.debug("Current mkek label: %s", self.current_mkek_label)
        LOG.debug("Current hmac label: %s", self.current_hmac_label)

        # cache current MKEK handle in the dictionary
        self.get_mkek(
            self.current_mkek_label,
            session
        )
        self.get_hmac_key(self.current_hmac_label, session)

        # Clean up the active session
        self.close_session(session)

    def perform_rng_self_test(self, session):
        test_random = self.generate_random(100, session)
        if self.ffi.buffer(test_random, 100)[:] == b"\x00" * 100:
            raise P11CryptoPluginException("Apparent RNG self-test failure.")

    def open_session(self, slot):
        session_ptr = self.ffi.new("CK_SESSION_HANDLE *")
        rv = self.lib.C_OpenSession(
            slot,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            self.ffi.NULL,
            self.ffi.NULL,
            session_ptr
        )
        self.check_error(rv)
        session = session_ptr[0]
        return session

    def close_session(self, session):
        rv = self.lib.C_CloseSession(session)
        self.check_error(rv)

    def login(self, password, session):
        rv = self.lib.C_Login(
            session,
            CKU_USER,
            password,
            len(password)
        )
        self.check_error(rv)

    def create_working_session(self):
        """Automatically opens a session and performs a login."""
        session = self.open_session(self.slot_id)
        self.login(self.login_passphrase, session)
        return session

    def check_error(self, value):
        if value != CKR_OK:
            raise P11CryptoPluginException(u._(
                "HSM returned response code: {hex_value} {code}").format(
                    hex_value=hex(value),
                    code=ERROR_CODES.get(value, 'CKR_????')
            )
            )

    def build_attributes(self, attrs):
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

        return CKAttributes(attributes, val_list)

    def get_mkek(self, mkek_label, session):
        mkek = self.get_key_handle(mkek_label, session)
        if not mkek:
            raise P11CryptoKeyHandleException()

        self.key_handles[mkek_label] = mkek

        return mkek

    def generate_mkek(self, mkek_label, mkek_length, session):

        # Generate a key that is persistent and not extractable
        ck_attributes = self.build_attributes([
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
        mkek = self.generate_kek(ck_attributes.template, session)

        self.key_handles[mkek_label] = mkek

        return mkek

    def get_hmac_key(self, hmac_label, session):
        hmac_key = self.get_key_handle(hmac_label, session)
        if not hmac_key:
            raise P11CryptoKeyHandleException()

        self.key_handles[hmac_label] = hmac_key

        return hmac_key

    def generate_hmac_key(self, hmac_label, session):
        # Generate a key that is persistent and not extractable
        ck_attributes = self.build_attributes([
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
        hmac_key = self.generate_kek(ck_attributes.template, session)

        self.key_handles[hmac_label] = hmac_key

        return hmac_key

    def get_key_handle(self, mkek_label, session):
        if mkek_label in self.key_handles:
            return self.key_handles[mkek_label]

        ck_attributes = self.build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, CKK_AES),
            Attribute(CKA_LABEL, mkek_label)
        ])
        rv = self.lib.C_FindObjectsInit(
            session, ck_attributes.template, len(ck_attributes.template)
        )
        self.check_error(rv)

        returned_count = self.ffi.new("CK_ULONG *")
        object_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE *")
        rv = self.lib.C_FindObjects(
            session, object_handle_ptr, 2, returned_count
        )
        self.check_error(rv)
        if returned_count[0] == 1:
            key = object_handle_ptr[0]
        rv = self.lib.C_FindObjectsFinal(session)
        self.check_error(rv)
        if returned_count[0] == 1:
            return key
        elif returned_count[0] == 0:
            return None
        else:
            raise P11CryptoPluginKeyException()

    def generate_random(self, length, session):
        buf = self.ffi.new("CK_BYTE[{0}]".format(length))
        rv = self.lib.C_GenerateRandom(session, buf, length)
        self.check_error(rv)
        return buf

    def build_gcm_mech(self, iv):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.algorithm
        gcm = self.ffi.new("CK_AES_GCM_PARAMS *")
        gcm.pIv = iv
        gcm.ulIvLen = 16
        gcm.ulIvBits = 128
        gcm.ulTagBits = 128
        mech.parameter = gcm
        mech.parameter_len = 48  # sizeof(CK_AES_GCM_PARAMS)
        return CKMechanism(mech, gcm)

    def generate_kek(self, template, session):
        """Generates both master and project KEKs

        :param template: A tuple of tuples in (CKA_TYPE, VALUE) form
        """
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_KEY_GEN
        object_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE *")
        rv = self.lib.C_GenerateKey(
            session, mech, template, len(template), object_handle_ptr
        )

        self.check_error(rv)
        return object_handle_ptr[0]

    def generate_wrapped_kek(self, kek_label, key_length, session):
        # generate a non-persistent key that is extractable
        ck_attributes = self.build_attributes([
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
        kek = self.generate_kek(ck_attributes.template, session)
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_CBC_PAD
        iv = self.generate_random(16, session)
        mech.parameter = iv
        mech.parameter_len = 16
        mkek = self.key_handles[self.current_mkek_label]
        # Since we're using CKM_AES_CBC_PAD the maximum length of the
        # padded key will be the key length + one block. We allocate the
        # worst case scenario as a CK_BYTE array.
        padded_length = key_length + self.block_size

        buf = self.ffi.new("CK_BYTE[{0}]".format(padded_length))
        buf_len = self.ffi.new("CK_ULONG *", padded_length)
        rv = self.lib.C_WrapKey(session, mech, mkek, kek, buf, buf_len)
        self.check_error(rv)
        wrapped_key = self.ffi.buffer(buf, buf_len[0])[:]
        hmac = self.compute_hmac(wrapped_key, session)
        return {
            'iv': base64.b64encode(self.ffi.buffer(iv)[:]),
            'wrapped_key': base64.b64encode(wrapped_key),
            'hmac': base64.b64encode(hmac),
            'mkek_label': self.current_mkek_label,
            'hmac_label': self.current_hmac_label
        }

    def compute_hmac(self, wrapped_key, session):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_SHA256_HMAC
        hmac_key = self.key_handles[self.current_hmac_label]
        rv = self.lib.C_SignInit(session, mech, hmac_key)
        self.check_error(rv)

        ck_bytes = self.ffi.new("CK_BYTE[]", wrapped_key)
        buf = self.ffi.new("CK_BYTE[32]")
        buf_len = self.ffi.new("CK_ULONG *", 32)
        rv = self.lib.C_Sign(session, ck_bytes, len(wrapped_key), buf, buf_len)
        self.check_error(rv)
        return self.ffi.buffer(buf, buf_len[0])[:]

    def verify_hmac(self, hmac_key, sig, wrapped_key, session):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_SHA256_HMAC

        rv = self.lib.C_VerifyInit(session, mech, hmac_key)
        self.check_error(rv)
        ck_bytes = self.ffi.new("CK_BYTE[]", wrapped_key)
        ck_sig = self.ffi.new("CK_BYTE[]", sig)
        rv = self.lib.C_Verify(
            session, ck_bytes, len(wrapped_key), ck_sig, len(sig)
        )
        self.check_error(rv)

    def unwrap_key(self, plugin_meta, session):
        """Unwraps byte string to key handle in HSM.

        :param plugin_meta: kek_meta_dto plugin meta (json string)
        :returns: Key handle from HSM. No unencrypted bytes.
        """
        meta = json.loads(plugin_meta)
        iv = base64.b64decode(meta['iv'])
        hmac = base64.b64decode(meta['hmac'])
        wrapped_key = base64.b64decode(meta['wrapped_key'])
        mkek = self.get_key_handle(meta['mkek_label'], session)
        hmac_key = self.get_key_handle(meta['hmac_label'], session)
        LOG.debug("Unwrapping key with %s mkek label", meta['mkek_label'])

        LOG.debug("Verifying key with %s hmac label", meta['hmac_label'])
        self.verify_hmac(hmac_key, hmac, wrapped_key, session)

        unwrapped = self.ffi.new("CK_OBJECT_HANDLE *")
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = CKM_AES_CBC_PAD
        iv = self.ffi.new("CK_BYTE[]", iv)
        mech.parameter = iv
        mech.parameter_len = 16

        ck_attributes = self.build_attributes([
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
            session, mech, mkek, wrapped_key, len(wrapped_key),
            ck_attributes.template, len(ck_attributes.template), unwrapped
        )
        self.check_error(rv)

        return unwrapped[0]

    def pad(self, unencrypted):
        padder = padding.PKCS7(self.block_size * 8).padder()
        return padder.update(unencrypted) + padder.finalize()

    def unpad(self, unencrypted):
        unpadder = padding.PKCS7(self.block_size * 8).unpadder()
        return unpadder.update(unencrypted) + unpadder.finalize()
