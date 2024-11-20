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

import collections
import textwrap

import cffi
from cryptography.hazmat.primitives import padding

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u

LOG = utils.getLogger(__name__)

Attribute = collections.namedtuple("Attribute", ["type", "value"])
CKAttributes = collections.namedtuple("CKAttributes", ["template", "cffivals"])
CKMechanism = collections.namedtuple("CKMechanism", ["mech", "cffivals"])
Token = collections.namedtuple("Token", ["slot_id", "label", "serial_number"])

CKR_OK = 0
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CK_TRUE = 1
CKF_RW_SESSION = (1 << 1)
CKF_SERIAL_SESSION = (1 << 2)
CKF_OS_LOCKING_OK = 0x02
CKU_SO = 0
CKU_USER = 1

CKS_RO_PUBLIC_SESSION = 0
CKS_RO_USER_FUNCTIONS = 1
CKS_RW_PUBLIC_SESSION = 2
CKS_RW_USER_FUNCTIONS = 3

CKO_SECRET_KEY = 4
CKK_AES = 0x1f
CKK_GENERIC_SECRET = 0x10
CKK_SHA256_HMAC = 0x0000002B

_KEY_TYPES = {
    'CKK_AES': CKK_AES,
    'CKK_GENERIC_SECRET': CKK_GENERIC_SECRET,
    'CKK_SHA256_HMAC': CKK_SHA256_HMAC
}

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
CKM_AES_CBC = 0x1082
CKM_AES_MAC = 0x1083
CKM_AES_CBC_PAD = 0x1085
CKM_AES_GCM = 0x1087
CKM_AES_KEY_WRAP_PAD = 0x210A
CKM_AES_KEY_WRAP_KWP = 0x210B
CKM_GENERIC_SECRET_KEY_GEN = 0x350
VENDOR_SAFENET_CKM_AES_GCM = 0x8000011c

# nCipher Vendor-defined Mechanisms
CKM_NC_SHA256_HMAC_KEY_GEN = 0xDE436997

_ENCRYPTION_MECHANISMS = {
    'CKM_AES_CBC': CKM_AES_CBC,
    'CKM_AES_GCM': CKM_AES_GCM,
    'VENDOR_SAFENET_CKM_AES_GCM': VENDOR_SAFENET_CKM_AES_GCM,
}

_CBC_IV_SIZE = 16  # bytes
_CBC_BLOCK_SIZE = 128  # bits

# ----- Supported Mechanisms -----
# Barbican only supports the PKCS#11 mechanisms below

_KEY_GEN_MECHANISMS = {
    'CKM_AES_KEY_GEN': CKM_AES_KEY_GEN,
    'CKM_NC_SHA256_HMAC_KEY_GEN': CKM_NC_SHA256_HMAC_KEY_GEN,
    'CKM_GENERIC_SECRET_KEY_GEN': CKM_GENERIC_SECRET_KEY_GEN,
}

_HMAC_MECHANISMS = {
    'CKM_SHA256_HMAC': CKM_SHA256_HMAC,
    'CKM_AES_MAC': CKM_AES_MAC
}

_KEY_WRAP_MECHANISMS = {
    'CKM_AES_CBC_PAD': CKM_AES_CBC_PAD,
    'CKM_AES_KEY_WRAP_PAD': CKM_AES_KEY_WRAP_PAD,
    'CKM_AES_KEY_WRAP_KWP': CKM_AES_KEY_WRAP_KWP
}

CKM_NAMES = dict()
CKM_NAMES.update(_ENCRYPTION_MECHANISMS)
CKM_NAMES.update(_KEY_GEN_MECHANISMS)
CKM_NAMES.update(_HMAC_MECHANISMS)
CKM_NAMES.update(_KEY_WRAP_MECHANISMS)

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
    1 << 31: 'CKR_VENDOR_DEFINED',
    # Trustway Proteccio Codes
    0x81000071: 'EHOSTUNREACH'
}


def build_ffi():
    ffi = cffi.FFI()
    ffi.cdef(textwrap.dedent("""
    typedef unsigned char CK_BYTE;
    typedef CK_BYTE CK_CHAR;
    typedef CK_BYTE CK_UTF8CHAR;
    typedef CK_BYTE CK_BBOOL;
    typedef unsigned long CK_ULONG;
    typedef unsigned long CK_RV;
    typedef unsigned long CK_SESSION_HANDLE;
    typedef unsigned long CK_OBJECT_HANDLE;
    typedef unsigned long CK_SLOT_ID;
    typedef CK_SLOT_ID * CK_SLOT_ID_PTR;
    typedef unsigned long CK_FLAGS;
    typedef unsigned long CK_STATE;
    typedef unsigned long CK_USER_TYPE;
    typedef unsigned char * CK_UTF8CHAR_PTR;
    typedef void * CK_VOID_PTR;
    typedef CK_VOID_PTR * CK_VOID_PTR_PTR;
    typedef ... *CK_NOTIFY;

    typedef unsigned long ck_attribute_type_t;
    struct ck_attribute {
        ck_attribute_type_t type;
        void *value;
        unsigned long value_len;
    };
    typedef struct ck_attribute CK_ATTRIBUTE;
    typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

    typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR);
    typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR);
    typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR);
    typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR);

    typedef struct CK_C_INITIALIZE_ARGS {
        CK_CREATEMUTEX CreateMutex;
        CK_DESTROYMUTEX DestroyMutex;
        CK_LOCKMUTEX LockMutex;
        CK_UNLOCKMUTEX UnlockMutex;
        CK_FLAGS flags;
        CK_VOID_PTR pReserved;
    } CK_C_INITIALIZE_ARGS;

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

    typedef struct CK_VERSION {
        CK_BYTE major;
        CK_BYTE minor;
    } CK_VERSION;

    typedef struct CK_INFO {
        CK_VERSION  cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32];
        CK_FLAGS flags;
        CK_UTF8CHAR libraryDescription[32];
        CK_VERSION  libraryVersion;
    } CK_INFO;

    typedef CK_INFO * CK_INFO_PTR;

    typedef struct CK_SLOT_INFO {
        CK_UTF8CHAR slotDescription[64];
        CK_UTF8CHAR manufacturerID[32];
        CK_FLAGS    flags;

        CK_VERSION  hardwareVersion;
        CK_VERSION  firmwareVersion;
    } CK_SLOT_INFO;
    typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;

    typedef struct CK_TOKEN_INFO {
        CK_UTF8CHAR label[32];
        CK_UTF8CHAR manufacturerID[32];
        CK_UTF8CHAR model[16];
        CK_CHAR serialNumber[16];
        CK_FLAGS flags;

        CK_ULONG ulMaxSessionCount;
        CK_ULONG ulSessionCount;
        CK_ULONG ulMaxRwSessionCount;
        CK_ULONG ulRwSessionCount;
        CK_ULONG ulMaxPinLen;
        CK_ULONG ulMinPinLen;
        CK_ULONG ulTotalPublicMemory;
        CK_ULONG ulFreePublicMemory;
        CK_ULONG ulTotalPrivateMemory;
        CK_ULONG ulFreePrivateMemory;
        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;
        CK_CHAR utcTime[16];
    } CK_TOKEN_INFO;
    typedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;

    typedef struct ck_session_info {
        CK_SLOT_ID slot_id;
        CK_STATE state;
        CK_FLAGS flags;
        unsigned long device_error;
    } CK_SESSION_INFO;
    typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

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
    CK_RV C_Finalize(void *);
    CK_RV C_OpenSession(CK_SLOT_ID, CK_FLAGS, void *, CK_NOTIFY,
                        CK_SESSION_HANDLE *);
    CK_RV C_CloseSession(CK_SESSION_HANDLE);
    CK_RV C_GetSessionInfo(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
    CK_RV C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR,
                  CK_ULONG);
    CK_RV C_GetInfo(CK_INFO_PTR);
    CK_RV C_GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
    CK_RV C_GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);
    CK_RV C_GetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
    CK_RV C_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                              CK_ATTRIBUTE *, CK_ULONG);
    CK_RV C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                              CK_ATTRIBUTE *, CK_ULONG);
    CK_RV C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
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
    CK_RV C_SeedRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    """))
    return ffi


class PKCS11(object):
    def __init__(self, library_path, login_passphrase,
                 token_serial_number=None,
                 token_labels=None,
                 slot_id=None,
                 rw_session=True,
                 seed_random_buffer=None,
                 encryption_mechanism=None,
                 encryption_gen_iv=True,
                 always_set_cka_sensitive=True,
                 hmac_mechanism=None,
                 key_wrap_mechanism=None,
                 key_wrap_gen_iv=False,
                 os_locking_ok=False,
                 ffi=None):
        # Validate all mechanisms are supported
        if encryption_mechanism not in _ENCRYPTION_MECHANISMS:
            raise ValueError("Invalid Encryption mechanism.")
        if hmac_mechanism not in _HMAC_MECHANISMS:
            raise ValueError("Invalid HMAC signing mechanism.")
        if key_wrap_mechanism not in _KEY_WRAP_MECHANISMS:
            raise ValueError("Invalid Key Wrapping mechanism.")

        self.ffi = ffi or build_ffi()
        self.lib = self.ffi.dlopen(library_path)
        self._initialize_library(os_locking_ok)

        # Session options
        self.login_passphrase = _to_bytes(login_passphrase)
        self.rw_session = rw_session
        self.slot_id = self._get_slot_id(
            token_serial_number,
            token_labels,
            slot_id)

        # Algorithm options
        self.encrypt_mech = CKM_NAMES[encryption_mechanism]
        self.encrypt = getattr(
            self,
            '_{}_encrypt'.format(encryption_mechanism)
        )
        self.encrypt_gen_iv = encryption_gen_iv
        self.blocksize = 16
        self.noncesize = 12
        self.gcmtagsize = 16
        self.always_set_cka_sensitive = always_set_cka_sensitive
        self.hmac_mechanism = CKM_NAMES[hmac_mechanism]
        self.key_wrap_mechanism = key_wrap_mechanism
        self.key_wrap_gen_iv = key_wrap_gen_iv

        # Validate configuration and RNG
        session = self.get_session()
        if seed_random_buffer is not None:
            self._seed_random(session, seed_random_buffer)
        self._rng_self_test(session)
        self.return_session(session)
        LOG.debug("Connected to PCKS#11 Token in Slot %s", self.slot_id)

    def _initialize_library(self, os_locking_ok):
        if os_locking_ok:
            init_arg_pt = self.ffi.new("CK_C_INITIALIZE_ARGS *")
            init_arg_pt.flags = CKF_OS_LOCKING_OK
        else:
            init_arg_pt = self.ffi.NULL

        rv = self.lib.C_Initialize(init_arg_pt)
        self._check_error(rv)

    def _get_slot_id(self, token_serial_number, token_labels, slot_id):
        # First find out how many slots with tokens are available
        slots_ptr = self.ffi.new("CK_ULONG_PTR")
        rv = self.lib.C_GetSlotList(CK_TRUE, self.ffi.NULL, slots_ptr)
        self._check_error(rv)

        # Next get the Slot IDs for each of the available slots
        slot_ids_ptr = self.ffi.new("CK_SLOT_ID[{}]".format(slots_ptr[0]))
        rv = self.lib.C_GetSlotList(CK_TRUE, slot_ids_ptr, slots_ptr)
        self._check_error(rv)

        # Gather details from each token
        tokens = list()
        for id in slot_ids_ptr:
            token_info_ptr = self.ffi.new("CK_TOKEN_INFO_PTR")
            rv = self.lib.C_GetTokenInfo(id, token_info_ptr)
            self._check_error(rv)
            token = Token(
                id,
                self.ffi.string(token_info_ptr.label).decode("UTF-8").strip(),
                self.ffi.string(
                    token_info_ptr.serialNumber
                ).decode("UTF-8").strip()
            )
            LOG.debug("Slot %s: label: %s sn: %s",
                      token.slot_id,
                      token.label,
                      token.serial_number)
            tokens.append(token)

        # Matching serial number gets highest priority
        if token_serial_number:
            for token in tokens:
                if token.serial_number == token_serial_number:
                    LOG.debug("Found token sn: %s in slot %s",
                              token.serial_number,
                              token.slot_id)
                    if token_labels:
                        LOG.warning(
                            "Ignoring token_labels: %s from barbican.conf",
                            token_labels
                        )
                    if slot_id:
                        LOG.warning("Ignoring slot_id: %s from barbican.conf",
                                    slot_id)
                    return token.slot_id
            raise ValueError("Token Serial Number not found.")

        # Label match is next, raises an error if there's not exactly one match
        if token_labels:
            for token in tokens:
                if token.label in token_labels:
                    LOG.debug("Found token label: %s in slot %s", token.label,
                              token.slot_id)
                    if slot_id:
                        LOG.warning("Ignoring slot_id: %s from barbican.conf",
                                    slot_id)
                    return token.slot_id
            raise ValueError("Token Labels not found.")

        # If we got this far, slot_id was the only param given, so we return it
        return slot_id

    def get_session(self):
        session = self._open_session(self.slot_id)
        # Get session info to check user state
        session_info = self._get_session_info(session)
        if session_info.state in (CKS_RO_PUBLIC_SESSION,
                                  CKS_RW_PUBLIC_SESSION):
            # Login public sessions
            self._login(self.login_passphrase, session)
        return session

    def return_session(self, session):
        self._close_session(session)

    def generate_random(self, length, session):
        buf = self._generate_random(length, session)
        return self.ffi.buffer(buf)[:]

    def get_key_handle(self, key_type, label, session):
        attributes = self._build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, _KEY_TYPES[key_type]),
            Attribute(CKA_LABEL, str(label))
        ])
        rv = self.lib.C_FindObjectsInit(
            session, attributes.template, len(attributes.template)
        )
        self._check_error(rv)

        count = self.ffi.new("CK_ULONG *")
        obj_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE[2]")
        rv = self.lib.C_FindObjects(session, obj_handle_ptr, 2, count)
        self._check_error(rv)
        key = None
        if count[0] == 1:
            key = obj_handle_ptr[0]
        rv = self.lib.C_FindObjectsFinal(session)
        self._check_error(rv)
        if count[0] > 1:
            raise exception.P11CryptoPluginKeyException()
        return key

    def _CKM_AES_CBC_encrypt(self, key, pt_data, session):
        iv = self._generate_random(_CBC_IV_SIZE, session)
        ck_mechanism = self._build_cbc_mechanism(iv)
        rv = self.lib.C_EncryptInit(session, ck_mechanism.mech, key)
        self._check_error(rv)

        padder = padding.PKCS7(_CBC_BLOCK_SIZE).padder()
        padded_pt_data = padder.update(pt_data)
        padded_pt_data += padder.finalize()

        pt_len = len(padded_pt_data)
        ct_len = self.ffi.new("CK_ULONG *", pt_len)

        ct = self.ffi.new("CK_BYTE[{}]".format(ct_len[0]))
        rv = self.lib.C_Encrypt(session, padded_pt_data, pt_len, ct, ct_len)
        self._check_error(rv)

        return {
            "iv": self.ffi.buffer(iv)[:],
            "ct": self.ffi.buffer(ct, ct_len[0])[:]
        }

    def _build_cbc_mechanism(self, iv):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.encrypt_mech
        mech.parameter = iv
        mech.parameter_len = _CBC_IV_SIZE
        return CKMechanism(mech, None)

    def _CKM_AES_CBC_decrypt(self, key, iv, ct_data, session):
        iv = self.ffi.new("CK_BYTE[{}]".format(len(iv)), iv)
        ck_mechanism = self._build_cbc_mechanism(iv)
        rv = self.lib.C_DecryptInit(session, ck_mechanism.mech, key)
        self._check_error(rv)

        ct_len = len(ct_data)
        pt_len = self.ffi.new("CK_ULONG *", ct_len)
        pt = self.ffi.new("CK_BYTE[{0}]".format(pt_len[0]))
        rv = self.lib.C_Decrypt(session, ct_data, ct_len, pt, pt_len)
        self._check_error(rv)
        pt = self.ffi.buffer(pt, pt_len[0])[:]

        unpadder = padding.PKCS7(_CBC_BLOCK_SIZE).unpadder()
        unpadded_pt = unpadder.update(pt)
        unpadded_pt += unpadder.finalize()
        return unpadded_pt

    def _VENDOR_SAFENET_CKM_AES_GCM_encrypt(self, key, pt_data, session):
        iv = None
        if self.encrypt_gen_iv:
            iv = self._generate_random(self.noncesize, session)
        ck_mechanism = self._build_gcm_mechanism(iv)
        rv = self.lib.C_EncryptInit(session, ck_mechanism.mech, key)
        self._check_error(rv)

        pt_len = len(pt_data)
        if self.encrypt_gen_iv:
            ct_len = self.ffi.new("CK_ULONG *", pt_len + self.gcmtagsize)
        else:
            ct_len = self.ffi.new("CK_ULONG *", pt_len + self.gcmtagsize * 2)
        ct = self.ffi.new("CK_BYTE[{0}]".format(ct_len[0]))
        rv = self.lib.C_Encrypt(session, pt_data, pt_len, ct, ct_len)
        self._check_error(rv)

        if self.encrypt_gen_iv:
            return {
                "iv": self.ffi.buffer(iv)[:],
                "ct": self.ffi.buffer(ct, ct_len[0])[:]
            }
        else:
            # HSM-generated IVs are appended to the end of the ciphertext
            return {
                "iv": self.ffi.buffer(ct, ct_len[0])[-self.gcmtagsize:],
                "ct": self.ffi.buffer(ct, ct_len[0])[:-self.gcmtagsize]
            }

    def _build_gcm_mechanism(self, iv=None):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.encrypt_mech
        gcm = self.ffi.new("CK_AES_GCM_PARAMS *")

        if iv:
            iv_len = len(iv)
            gcm.pIv = iv
            gcm.ulIvLen = iv_len
            gcm.ulIvBits = iv_len * 8

        gcm.ulTagBits = self.gcmtagsize * 8
        mech.parameter = gcm
        mech.parameter_len = 48
        return CKMechanism(mech, gcm)

    def _VENDOR_SAFENET_CKM_AES_GCM_decrypt(self, key, iv, ct_data, session):
        iv = self.ffi.new("CK_BYTE[{0}]".format(len(iv)), iv)
        ck_mechanism = self._build_gcm_mechanism(iv)
        rv = self.lib.C_DecryptInit(session, ck_mechanism.mech, key)
        self._check_error(rv)

        ct_len = len(ct_data)
        pt_len = self.ffi.new("CK_ULONG *", ct_len)
        pt = self.ffi.new("CK_BYTE[{0}]".format(pt_len[0]))
        rv = self.lib.C_Decrypt(session, ct_data, ct_len, pt, pt_len)
        self._check_error(rv)
        pt = self.ffi.buffer(pt, pt_len[0])[:]

        # Secrets stored by the old code uses 16 byte IVs, while the new code
        # uses 12 byte IVs to be more efficient with GCM. We can use this to
        # detect secrets stored by the old code and perform padding removal.
        # If we find a 16 byte IV, we check to make sure the decrypted plain
        # text is a multiple of the block size, and then that the end of the
        # plain text looks like padding, ie the last character is a value
        # between 1 and blocksize, and that there are that many consecutive
        # bytes of that value at the end. If all of that is true, we remove
        # the found padding.
        last_byte = ord(pt[-1:])
        if len(iv) == self.blocksize and \
           (len(pt) % self.blocksize) == 0 and \
           1 <= last_byte <= self.blocksize and \
           pt.endswith(pt[-1:] * last_byte):
            pt = pt[:-last_byte]

        return pt

    def _CKM_AES_GCM_encrypt(self, key, pt_data, session):
        return self._VENDOR_SAFENET_CKM_AES_GCM_encrypt(key, pt_data, session)

    def _CKM_AES_GCM_decrypt(self, key, iv, ct_data, session):
        return self._VENDOR_SAFENET_CKM_AES_GCM_decrypt(
            key, iv, ct_data, session
        )

    def decrypt(self, mechanism, key, iv, ct_data, session):
        if mechanism not in _ENCRYPTION_MECHANISMS:
            raise ValueError(u._("Unsupported decryption mechanism"))
        return getattr(self, '_{}_decrypt'.format(mechanism))(
            key, iv, ct_data, session
        )

    def generate_key(self, key_type, key_length, mechanism, session,
                     key_label=None, master_key=False,
                     encrypt=False, sign=False, wrap=False):
        if not any((encrypt, sign, wrap)):
            raise exception.P11CryptoPluginException()
        if master_key and not key_label:
            raise ValueError(u._("key_label must be set for master_keys"))

        token = master_key
        extractable = not master_key
        # in some HSMs extractable keys cannot be marked sensitive
        sensitive = self.always_set_cka_sensitive or not extractable

        ck_attributes = [
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, _KEY_TYPES[key_type]),
            Attribute(CKA_VALUE_LEN, key_length),
            Attribute(CKA_TOKEN, token),
            Attribute(CKA_PRIVATE, True),
            Attribute(CKA_SENSITIVE, sensitive),
            Attribute(CKA_ENCRYPT, encrypt),
            Attribute(CKA_DECRYPT, encrypt),
            Attribute(CKA_SIGN, sign),
            Attribute(CKA_VERIFY, sign),
            Attribute(CKA_WRAP, wrap),
            Attribute(CKA_UNWRAP, wrap),
            Attribute(CKA_EXTRACTABLE, extractable)
        ]
        if master_key:
            ck_attributes.append(Attribute(CKA_LABEL, key_label))
        ck_attributes = self._build_attributes(ck_attributes)
        mech = self.ffi.new("CK_MECHANISM *")

        mech.mechanism = _KEY_GEN_MECHANISMS[mechanism]

        obj_handle_ptr = self.ffi.new("CK_OBJECT_HANDLE *")
        rv = self.lib.C_GenerateKey(
            session, mech, ck_attributes.template, len(ck_attributes.template),
            obj_handle_ptr
        )
        self._check_error(rv)

        return obj_handle_ptr[0]

    def wrap_key(self, wrapping_key, key_to_wrap, session):
        if self.key_wrap_gen_iv:
            iv_len = {
                'CKM_AES_CBC_PAD': 16,  # bytes
                'CKM_AES_KEY_WRAP_PAD': 8,  # bytes
                'CKM_AES_KEY_WRAP_KWP': 4   # bytes
            }.get(self.key_wrap_mechanism)
            iv = self._generate_random(iv_len, session)
        else:
            iv = None
        mech = self._build_key_wrap_mechanism(
            CKM_NAMES[self.key_wrap_mechanism],
            iv
        )

        # Ask for length of the wrapped key
        wrapped_key_len = self.ffi.new("CK_ULONG *")
        rv = self.lib.C_WrapKey(
            session, mech, wrapping_key, key_to_wrap,
            self.ffi.NULL, wrapped_key_len
        )
        self._check_error(rv)

        # Wrap key
        wrapped_key = self.ffi.new("CK_BYTE[{0}]".format(wrapped_key_len[0]))
        rv = self.lib.C_WrapKey(
            session, mech, wrapping_key, key_to_wrap,
            wrapped_key, wrapped_key_len
        )
        self._check_error(rv)

        return {
            'iv': iv and self.ffi.buffer(iv)[:],
            'wrapped_key': self.ffi.buffer(wrapped_key, wrapped_key_len[0])[:],
            'key_wrap_mechanism': self.key_wrap_mechanism
        }

    def _build_key_wrap_mechanism(self, mechanism, iv):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = mechanism
        if iv is not None:
            mech.parameter = iv
            mech.parameter_len = len(iv)
        return mech

    def unwrap_key(self, mechanism, wrapping_key, iv, wrapped_key, session):
        ck_wrapped_key = self.ffi.new("CK_BYTE[]", wrapped_key)
        ck_iv = iv and self.ffi.new("CK_BYTE[{}]".format(len(iv)), iv)
        unwrapped_key = self.ffi.new("CK_OBJECT_HANDLE *")
        mech = self._build_key_wrap_mechanism(
            CKM_NAMES[mechanism],
            ck_iv
        )

        ck_attributes = self._build_attributes([
            Attribute(CKA_CLASS, CKO_SECRET_KEY),
            Attribute(CKA_KEY_TYPE, CKK_AES),
            Attribute(CKA_TOKEN, False),
            Attribute(CKA_PRIVATE, True),
            Attribute(CKA_SENSITIVE, True),
            Attribute(CKA_ENCRYPT, True),
            Attribute(CKA_DECRYPT, True),
            Attribute(CKA_EXTRACTABLE, True)
        ])
        rv = self.lib.C_UnwrapKey(
            session, mech, wrapping_key, ck_wrapped_key, len(wrapped_key),
            ck_attributes.template, len(ck_attributes.template), unwrapped_key
        )
        self._check_error(rv)

        return unwrapped_key[0]

    def compute_hmac(self, hmac_key, data, session):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.hmac_mechanism
        rv = self.lib.C_SignInit(session, mech, hmac_key)
        self._check_error(rv)

        ck_data = self.ffi.new("CK_BYTE[]", data)
        buf = self.ffi.new("CK_BYTE[32]")
        buf_len = self.ffi.new("CK_ULONG *", 32)
        rv = self.lib.C_Sign(session, ck_data, len(data), buf, buf_len)
        self._check_error(rv)
        return self.ffi.buffer(buf, buf_len[0])[:]

    def verify_hmac(self, hmac_key, sig, data, session):
        mech = self.ffi.new("CK_MECHANISM *")
        mech.mechanism = self.hmac_mechanism

        rv = self.lib.C_VerifyInit(session, mech, hmac_key)
        self._check_error(rv)
        ck_data = self.ffi.new("CK_BYTE[]", data)
        ck_sig = self.ffi.new("CK_BYTE[]", sig)
        rv = self.lib.C_Verify(session, ck_data, len(data), ck_sig, len(sig))
        self._check_error(rv)

    def destroy_object(self, obj_handle, session):
        rv = self.lib.C_DestroyObject(session, obj_handle)
        self._check_error(rv)

    def finalize(self):
        rv = self.lib.C_Finalize(self.ffi.NULL)
        try:
            self._check_error(rv)
        except exception.TrustwayProteccioException:
            LOG.warning("Trustway Proteccio client failed to finalize.")

    def _check_error(self, value):
        if value != CKR_OK and value != CKR_CRYPTOKI_ALREADY_INITIALIZED:
            code = ERROR_CODES.get(value, 'CKR_????')
            hex_code = "{hex} {code}".format(hex=hex(value), code=code)

            if code == 'CKR_TOKEN_NOT_PRESENT':
                raise exception.P11CryptoTokenException(slot_id=self.slot_id)

            if code == 'EHOSTUNREACH':
                raise exception.TrustwayProteccioException(
                    "Trustway Proteccio Error: {code}".format(code=hex_code))

            raise exception.P11CryptoPluginException(u._(
                "HSM returned response code: {code}").format(code=hex_code))

    def _seed_random(self, session, seed_random_buffer):
        """Call the C_SeedRandom() function with the seed_random data"""
        buf = self.ffi.new("CK_BYTE[]", seed_random_buffer.encode())
        rv = self.lib.C_SeedRandom(session, buf, len(seed_random_buffer))
        self._check_error(rv)

    def _generate_random(self, length, session):
        buf = self.ffi.new("CK_BYTE[{0}]".format(length))
        rv = self.lib.C_GenerateRandom(session, buf, length)
        self._check_error(rv)
        return buf

    def _build_attributes(self, attrs):
        attributes = self.ffi.new("CK_ATTRIBUTE[{0}]".format(len(attrs)))
        val_list = []
        for index, attr in enumerate(attrs):
            attributes[index].type = attr.type
            if isinstance(attr.value, bool):
                val_list.append(self.ffi.new("unsigned char *",
                                int(attr.value)))
                attributes[index].value_len = 1  # sizeof(char) is 1
            elif isinstance(attr.value, int):
                # second because bools are also considered ints
                val_list.append(self.ffi.new("CK_ULONG *", attr.value))
                attributes[index].value_len = 8
            elif isinstance(attr.value, str):
                buf = attr.value.encode('utf-8')
                val_list.append(self.ffi.new("char []", buf))
                attributes[index].value_len = len(buf)
            elif isinstance(attr.value, bytes):
                val_list.append(self.ffi.new("char []", attr.value))
                attributes[index].value_len = len(attr.value)
            else:
                raise TypeError(u._("Unknown attribute type provided."))

            attributes[index].value = val_list[-1]

        return CKAttributes(attributes, val_list)

    def _open_session(self, slot):
        session_ptr = self.ffi.new("CK_SESSION_HANDLE *")
        flags = CKF_SERIAL_SESSION
        if self.rw_session:
            flags |= CKF_RW_SESSION
        rv = self.lib.C_OpenSession(slot, flags, self.ffi.NULL,
                                    self.ffi.NULL, session_ptr)
        self._check_error(rv)
        return session_ptr[0]

    def _close_session(self, session):
        rv = self.lib.C_CloseSession(session)
        self._check_error(rv)

    def _get_session_info(self, session):
        session_info_ptr = self.ffi.new("CK_SESSION_INFO *")
        rv = self.lib.C_GetSessionInfo(session, session_info_ptr)
        self._check_error(rv)
        return session_info_ptr[0]

    def _login(self, password, session):
        rv = self.lib.C_Login(session, CKU_USER, password, len(password))
        self._check_error(rv)

    def _rng_self_test(self, session):
        test_random = self.generate_random(100, session)
        if test_random == b'\x00' * 100:
            raise exception.P11CryptoPluginException(
                u._("Apparent RNG self-test failure."))


def _to_bytes(string):
    if isinstance(string, bytes):
        return string
    else:
        return string.encode('UTF-8')
