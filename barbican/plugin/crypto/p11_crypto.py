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

import base64
import collections
import threading
import time

from oslo_config import cfg
from oslo_serialization import jsonutils as json

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin.crypto import base as plugin
from barbican.plugin.crypto import pkcs11

CONF = config.new_config()
LOG = utils.getLogger(__name__)

CachedKEK = collections.namedtuple("CachedKEK", ["kek", "expires"])

p11_crypto_plugin_group = cfg.OptGroup(name='p11_crypto_plugin',
                                       title="PKCS11 Crypto Plugin Options")
p11_crypto_plugin_opts = [
    cfg.StrOpt('library_path',
               help=u._('Path to vendor PKCS11 library')),
    cfg.StrOpt('token_serial_number',
               help=u._('Token serial number used to identify the token to be '
                        'used.')),
    cfg.StrOpt('token_label',
               deprecated_for_removal=True,
               help=u._('DEPRECATED: Use token_labels instead. '
                        'Token label used to identify the token to '
                        'be used.')),
    cfg.ListOpt('token_labels',
                help=u._('List of labels for one or more tokens to be used. '
                         'Typically this is a single label, but some HSM '
                         'devices may require more than one label for Load '
                         'Balancing or High Availability configurations.')),
    cfg.StrOpt('login',
               help=u._('Password to login to PKCS11 session'),
               secret=True),
    cfg.StrOpt('mkek_label',
               help=u._('Master KEK label (as stored in the HSM)')),
    cfg.IntOpt('mkek_length',
               help=u._('Master KEK length in bytes.')),
    cfg.StrOpt('hmac_label',
               help=u._('Master HMAC Key label (as stored in the HSM)')),
    cfg.IntOpt('slot_id',
               help=u._('(Optional) HSM Slot ID that contains the token '
                        'device to be used.'),
               default=1),
    cfg.BoolOpt('rw_session',
                help=u._('Flag for Read/Write Sessions'),
                default=True),
    cfg.IntOpt('pkek_length',
               help=u._('Project KEK length in bytes.'),
               default=32),
    cfg.IntOpt('pkek_cache_ttl',
               help=u._('Project KEK Cache Time To Live, in seconds'),
               default=900),
    cfg.IntOpt('pkek_cache_limit',
               help=u._('Project KEK Cache Item Limit'),
               default=100),
    cfg.StrOpt('encryption_mechanism',
               help=u._('Secret encryption mechanism'),
               default='CKM_AES_CBC', deprecated_name='algorithm'),
    cfg.StrOpt('hmac_key_type',
               help=u._('HMAC Key Type'),
               default='CKK_AES'),
    cfg.StrOpt('hmac_keygen_mechanism',
               help=u._('HMAC Key Generation Algorithm'),
               default='CKM_AES_KEY_GEN'),
    cfg.StrOpt('hmac_keywrap_mechanism',
               help=u._('HMAC key wrap mechanism'),
               default='CKM_SHA256_HMAC'),
    cfg.StrOpt('seed_file',
               help=u._('File to pull entropy for seeding RNG'),
               default=''),
    cfg.IntOpt('seed_length',
               help=u._('Amount of data to read from file for seed'),
               default=32),
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='PKCS11 HSM'),
    cfg.BoolOpt('aes_gcm_generate_iv',
                help=u._('Generate IVs for CKM_AES_GCM mechanism.'),
                default=True, deprecated_name='generate_iv'),
    cfg.BoolOpt('always_set_cka_sensitive',
                help=u._('Always set CKA_SENSITIVE=CK_TRUE including '
                         'CKA_EXTRACTABLE=CK_TRUE keys.'),
                default=True),
    cfg.BoolOpt('os_locking_ok',
                help=u._('Enable CKF_OS_LOCKING_OK flag when initializing the '
                         'PKCS#11 client library.'),
                default=False),
]
CONF.register_group(p11_crypto_plugin_group)
CONF.register_opts(p11_crypto_plugin_opts, group=p11_crypto_plugin_group)
config.parse_args(CONF)


def list_opts():
    yield p11_crypto_plugin_group, p11_crypto_plugin_opts


def register_opts(conf):
    for group, options in list_opts():
        conf.register_opts(options, group)


def json_dumps_compact(data):
    return json.dumps(data, separators=(',', ':'))


class P11CryptoPlugin(plugin.CryptoPluginBase):
    """PKCS11 supporting implementation of the crypto plugin.

    """

    def __init__(self, conf=CONF, ffi=None, pkcs11=None):
        self.conf = conf
        plugin_conf = conf.p11_crypto_plugin

        # Save conf arguments
        if plugin_conf.library_path is None:
            raise ValueError(u._("library_path is required"))
        self.library_path = plugin_conf.library_path

        self.encryption_mechanism = plugin_conf.encryption_mechanism
        self.generate_iv = plugin_conf.aes_gcm_generate_iv
        self.cka_sensitive = plugin_conf.always_set_cka_sensitive
        self.mkek_key_type = 'CKK_AES'
        self.mkek_length = plugin_conf.mkek_length
        self.mkek_label = plugin_conf.mkek_label
        self.hmac_label = plugin_conf.hmac_label
        self.hmac_key_type = plugin_conf.hmac_key_type
        self.hmac_keygen_mechanism = plugin_conf.hmac_keygen_mechanism
        self.hmac_keywrap_mechanism = plugin_conf.hmac_keywrap_mechanism
        self.os_locking_ok = plugin_conf.os_locking_ok
        self.pkek_length = plugin_conf.pkek_length
        self.pkek_cache_ttl = plugin_conf.pkek_cache_ttl
        self.pkek_cache_limit = plugin_conf.pkek_cache_limit
        self.rw_session = plugin_conf.rw_session
        self.seed_file = plugin_conf.seed_file
        self.seed_length = plugin_conf.seed_length
        self.slot_id = plugin_conf.slot_id
        self.login = plugin_conf.login
        self.token_serial_number = plugin_conf.token_serial_number
        self.token_labels = plugin_conf.token_labels or list()
        if plugin_conf.token_label:
            LOG.warning('Using deprecated option "token_label". Please update '
                        'your configuration file.')
            if plugin_conf.token_label not in self.token_labels:
                self.token_labels.append(plugin_conf.token_label)

        # Use specified or create new pkcs11 object
        self.pkcs11 = pkcs11 or self._create_pkcs11(ffi)

        self._configure_object_cache()

    def get_plugin_name(self):
        return self.conf.p11_crypto_plugin.plugin_name

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        return self._call_pkcs11(self._encrypt, encrypt_dto, kek_meta_dto,
                                 project_id)

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                project_id):
        return self._call_pkcs11(self._decrypt, decrypt_dto, kek_meta_dto,
                                 kek_meta_extended, project_id)

    def bind_kek_metadata(self, kek_meta_dto):
        return self._call_pkcs11(self._bind_kek_metadata, kek_meta_dto)

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        return self._call_pkcs11(self._generate_symmetric, generate_dto,
                                 kek_meta_dto, project_id)

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

    def _call_pkcs11(self, func, *args, **kwargs):
        # Wrap pkcs11 calls to enable a single retry when exceptions are raised
        # that can be fixed by reinitializing the pkcs11 library
        try:
            if self.pkcs11 is None:
                self._reinitialize_pkcs11()
            return func(*args, **kwargs)
        except (exception.PKCS11Exception) as pe:
            LOG.warning("Reinitializing PKCS#11 library: %s", pe)
            self._reinitialize_pkcs11()
            return func(*args, **kwargs)

    def _encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        kek = self._load_kek_from_meta_dto(kek_meta_dto)
        try:
            session = self._get_session()
            ct_data = self.pkcs11.encrypt(
                kek, encrypt_dto.unencrypted, session
            )
        finally:
            if 'session' in locals():
                self._return_session(session)

        kek_meta_extended = json_dumps_compact({
            'iv': base64.b64encode(ct_data['iv']),
            'mechanism': self.encryption_mechanism
        })
        return plugin.ResponseDTO(ct_data['ct'], kek_meta_extended)

    def _decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended,
                 project_id):
        kek = self._load_kek_from_meta_dto(kek_meta_dto)
        meta_extended = json.loads(kek_meta_extended)
        iv = base64.b64decode(meta_extended['iv'])
        mech = meta_extended['mechanism']

        try:
            session = self._get_session()
            pt_data = self.pkcs11.decrypt(
                mech, kek, iv, decrypt_dto.encrypted, session
            )
        finally:
            if 'session' in locals():
                self._return_session(session)

        return pt_data

    def _bind_kek_metadata(self, kek_meta_dto):
        if not kek_meta_dto.plugin_meta:
            # Generate wrapped kek and jsonify
            wkek = self._generate_wrapped_kek(
                self.pkek_length, kek_meta_dto.kek_label
            )

            # Persisted by Barbican
            kek_meta_dto.plugin_meta = json_dumps_compact(wkek)
            kek_meta_dto.algorithm = 'AES'
            kek_meta_dto.bit_length = self.pkek_length * 8
            kek_meta_dto.mode = 'CBC'
        return kek_meta_dto

    def _generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        kek = self._load_kek_from_meta_dto(kek_meta_dto)
        byte_length = int(generate_dto.bit_length) // 8

        try:
            session = self._get_session()
            buf = self.pkcs11.generate_random(byte_length, session)
            ct_data = self.pkcs11.encrypt(kek, buf, session)
        finally:
            if 'session' in locals():
                self._return_session(session)

        kek_meta_extended = json_dumps_compact(
            {'iv': base64.b64encode(ct_data['iv']),
             'mechanism': self.encryption_mechanism}
        )
        return plugin.ResponseDTO(ct_data['ct'], kek_meta_extended)

    def _configure_object_cache(self):
        # Master Key cache
        self.mk_cache = {}
        self.mk_cache_lock = threading.RLock()

        # Project KEK cache
        self.pkek_cache = collections.OrderedDict()
        self.pkek_cache_lock = threading.RLock()

        # Session for object caching
        self.caching_session = self._get_session()
        self.caching_session_lock = threading.RLock()

        # Cache master keys
        self._get_master_key(self.mkek_key_type, self.mkek_label)
        self._get_master_key(self.hmac_key_type, self.hmac_label)

    def _pkek_cache_add(self, kek, label):
        with self.pkek_cache_lock:
            if label in self.pkek_cache:
                raise ValueError('{0} is already in the cache'.format(label))
            now = int(time.time())
            ckek = CachedKEK(kek, now + self.pkek_cache_ttl)
            if len(self.pkek_cache) >= self.pkek_cache_limit:
                with self.caching_session_lock:
                    session = self.caching_session
                    self._pkek_cache_expire(now, session)
                    # Test again if call above didn't remove any items
                    if len(self.pkek_cache) >= self.pkek_cache_limit:
                        (l, k) = self.pkek_cache.popitem(last=False)
                        self.pkcs11.destroy_object(k.kek, session)
            self.pkek_cache[label] = ckek

    def _pkek_cache_get(self, label, default=None):
        kek = default
        with self.pkek_cache_lock:
            ckek = self.pkek_cache.get(label)
            if ckek is not None:
                if int(time.time()) < ckek.expires:
                    kek = ckek.kek
                else:
                    with self.caching_session_lock:
                        self.pkcs11.destroy_object(ckek.kek,
                                                   self.caching_session)
                        del self.pkek_cache[label]
        return kek

    def _pkek_cache_expire(self, now, session):
        # Look for expired items, starting from oldest
        for (label, kek) in self.pkek_cache.items():
            if now >= kek.expires:
                self.pkcs11.destroy_object(kek.kek, session)
                del self.pkek_cache[label]
            else:
                break

    def _create_pkcs11(self, ffi=None):
        seed_random_buffer = None
        if self.seed_file:
            with open(self.seed_file, 'rb') as f:
                seed_random_buffer = f.read(self.seed_length)
        return pkcs11.PKCS11(
            library_path=self.library_path,
            login_passphrase=self.login,
            rw_session=self.rw_session,
            slot_id=self.slot_id,
            encryption_mechanism=self.encryption_mechanism,
            ffi=ffi,
            seed_random_buffer=seed_random_buffer,
            generate_iv=self.generate_iv,
            always_set_cka_sensitive=self.cka_sensitive,
            hmac_keywrap_mechanism=self.hmac_keywrap_mechanism,
            token_serial_number=self.token_serial_number,
            token_labels=self.token_labels,
            os_locking_ok=self.os_locking_ok
        )

    def _reinitialize_pkcs11(self):
        if self.pkcs11 is not None:
            self.pkcs11.finalize()
        self.pkcs11 = None

        with self.caching_session_lock:
            self.caching_session = None

        with self.pkek_cache_lock:
            self.pkek_cache.clear()

        with self.mk_cache_lock:
            self.mk_cache.clear()

        self.pkcs11 = self._create_pkcs11()
        self._configure_object_cache()

    def _get_session(self):
        return self.pkcs11.get_session()

    def _return_session(self, session):
        self.pkcs11.return_session(session)

    def _get_master_key(self, key_type, label):
        with self.mk_cache_lock:
            session = self.caching_session
            key = self.mk_cache.get(label, None)
            if key is None:
                with self.caching_session_lock:
                    key = self.pkcs11.get_key_handle(key_type, label, session)
                if key is None:
                    raise exception.P11CryptoKeyHandleException(
                        u._("Could not find key labeled {0}").format(label)
                    )
                self.mk_cache[label] = key
        return key

    def _load_kek_from_meta_dto(self, kek_meta_dto):
        meta = json.loads(kek_meta_dto.plugin_meta)
        kek = self._load_kek(
            kek_meta_dto.kek_label, meta['iv'], meta['wrapped_key'],
            meta['hmac'], meta['mkek_label'], meta['hmac_label']
        )
        return kek

    def _load_kek(self, key_label, iv, wrapped_key, hmac,
                  mkek_label, hmac_label):
        with self.pkek_cache_lock:
            kek = self._pkek_cache_get(key_label)
            if kek is None:
                # Decode data
                iv = base64.b64decode(iv)
                wrapped_key = base64.b64decode(wrapped_key)
                hmac = base64.b64decode(hmac)
                kek_data = iv + wrapped_key

                with self.caching_session_lock:
                    session = self.caching_session
                    # Get master keys
                    mkek = self._get_master_key(self.mkek_key_type, mkek_label)
                    mkhk = self._get_master_key(self.hmac_key_type, hmac_label)

                    # Verify HMAC
                    self.pkcs11.verify_hmac(mkhk, hmac, kek_data, session)

                    # Unwrap KEK
                    kek = self.pkcs11.unwrap_key(mkek, iv, wrapped_key,
                                                 session)

                self._pkek_cache_add(kek, key_label)

        return kek

    def _generate_wrapped_kek(self, key_length, key_label):
        with self.caching_session_lock:
            session = self.caching_session
            # Get master keys
            mkek = self._get_master_key(self.mkek_key_type, self.mkek_label)
            mkhk = self._get_master_key(self.hmac_key_type, self.hmac_label)

            # Generate KEK
            kek = self.pkcs11.generate_key(
                'CKK_AES', key_length, 'CKM_AES_KEY_GEN', session, encrypt=True
            )

            # Wrap KEK
            wkek = self.pkcs11.wrap_key(mkek, kek, session)

            # HMAC Wrapped KEK
            wkek_data = wkek['iv'] + wkek['wrapped_key']
            wkek_hmac = self.pkcs11.compute_hmac(mkhk, wkek_data, session)

        # Cache KEK
        self._pkek_cache_add(kek, key_label)

        return {
            'iv': base64.b64encode(wkek['iv']),
            'wrapped_key': base64.b64encode(wkek['wrapped_key']),
            'hmac': base64.b64encode(wkek_hmac),
            'mkek_label': self.mkek_label,
            'hmac_label': self.hmac_label
        }
