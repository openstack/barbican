.. _barbican_backend:

Configure Secret Store Back-end
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Key Manager service has a plugin architecture that allows the deployer to
store secrets in one or more secret stores.  Secret stores can be
software-based such as a software-only encryption mechanism, or hardware
devices such as a hardware security module (HSM).

Secret Stores implement both the encryption mechanisms as well as the storage
of the encrypted secrets.

This section compares all the plugins that are currently available and the
security tradeoffs that need to be considered when deciding which plugins to
use.

Simple Crypto Plugin
^^^^^^^^^^^^^^^^^^^^

This back end plugin implements encryption using only software.  The encrypted
secrets are stored in the Barbican database.

This crypto plugin is configured by default in ``/etc/barbican/barbican.conf``.

This plugin uses single symmetric key (kek - or 'key encryption key')
- which is stored in plain text in the ``/etc/barbican/barbican.conf`` file to encrypt
and decrypt all secrets.

+------------------+--------------------------------------------------------+
| Security         | ⚠ Master Key (KEK) stored in the configuration file    |
+------------------+--------------------------------------------------------+
| Maturity         | ✅ Tested on every patch                               |
+------------------+--------------------------------------------------------+
| Ease of Use      | | ✅ Simple to deploy                                  |
|                  | | ❌ Key rotation is disruptive                        |
|                  | | (all secrets must be re-encrypted)                   |
+------------------+--------------------------------------------------------+
| Scalability      | | ✅ Storage can be scaled in SQL DB                   |
|                  | | ✅ Failover/HA is simple, just run more barbican-api |
|                  |   instances                                            |
|                  | | ✅ High performance - Software crypto is fast        |
+------------------+--------------------------------------------------------+
| Cost             | ✅ Free (as in beer)                                   |
+------------------+--------------------------------------------------------+

.. warning::

    This plugin stores its KEK in plain text in the configuration file,
    which will be present in any node running the `barbican-api` or
    `barbican-worker` services.  Extreme care should be taken to prevent
    unauthorized access to these nodes.  When using this plugin the KEK is the
    only thing protecting the secrets stored in the database.

The configuration for this plugin in ``/etc/barbican/barbican.conf`` is as follows:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       # ================= Crypto plugin ===================
       [crypto]
       ..
       enabled_crypto_plugins = simple_crypto

       [simple_crypto_plugin]
       # the kek should be a 32-byte value which is base64 encoded
       kek = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY='

.. note::

   Setting crypto plugins has effect only when `secretstore` plugin is set to
   `store_crypto` unless multibackend storage is used.
   So, for example, using vault for secretstore and PKCS#11 for crypto will not
   work (vault will be responsible for both storage and encryption).


PKCS#11 Crypto Plugin
^^^^^^^^^^^^^^^^^^^^^

This crypto plugin can be used to interface with a Hardware Security Module (HSM)
using the PKCS#11 protocol.

Secrets are encrypted (and decrypted on retrieval) by a project specific
Key Encryption Key (KEK), which in it's turn encrypted with Master Key (MKEK)
and signed with HMAC key. Both MKEK and HMAC resides in the HSM.

The configuration for this plugin in ``/etc/barbican/barbican.conf``.
Settings for some different HSMs are provided below:

Thales Luna Network HSM (Safenet)
+++++++++++++++++++++++++++++++++

The PKCS#11 plugin configuration for Luna Network HSM looks like:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       # ================= Crypto plugin ===================
       [crypto]
       ..
       enabled_crypto_plugins = p11_crypto

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/usr/lib/libCryptoki2_64.so'

       # Token serial number used to identify the token to be used.  Required
       # when the device has multiple tokens with the same label. (string
       # value)
       #token_serial_number = 12345678

       # Token label used to identify the token to be used.  Required when
       # token_serial_number is not specified. (string value)
       #token_label = <None>

       # Password to login to PKCS11 session
       login = 'mypassword'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'my_mkek_label'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'my_hmac_label'

       # (Optional) HSM Slot ID that contains the token device to be used.
       # (integer value)
       slot_id = 1


       # Enable Read/Write session with the HSM?
       # rw_session = True

       # Length of Project KEKs to create
       # pkek_length = 32

       # How long to cache unwrapped Project KEKs
       # pkek_cache_ttl = 900

       # Max number of items in pkek cache
       # pkek_cache_limit = 100

.. note::

   Barbican does not support FIPS mode enabled for SafeNet Luna HSM or
   Data Protection on Demand HSM. Make sure that it's operating in non-FIPS
   mode while integrating with Barbican.

The HMAC and MKEK keys can be generated as follows:

    .. code-block:: ini

       barbican-manage hsm gen_hmac --library-path /usr/lib/libCryptoki2_64.so \
       --passphrase XXX --slot-id 1 --label my_hmac_label

    .. code-block:: ini

       barbican-manage hsm gen_mkek --library-path /usr/lib/libCryptoki2_64.so \
       --passphrase XXX --slot-id 1 --label my_mkek_label

nCipher
+++++++

For a nCipher nShield Connect XC, the plugin configuration looks like:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       # ================= Crypto plugin ===================
       [crypto]
       ..
       enabled_crypto_plugins = p11_crypto

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/opt/nfast/toolkits/pkcs11/libcknfast.so'

       # Token serial number used to identify the token to be used.  Required
       # when the device has multiple tokens with the same label. (string
       # value)
       token_serial_number = 12345678

       # Token label used to identify the token to be used.  Required when
       # token_serial_number is not specified. (string value)
       #token_label = <None>

       # Password to login to PKCS11 session
       login = 'XXX'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'thales_mkek_0'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'thales_hmac_0'

       # (Optional) HSM Slot ID that contains the token device to be used.
       # (integer value)
       # slot_id = 1

       # Enable Read/Write session with the HSM?
       # rw_session = True

       # Length of Project KEKs to create
       # pkek_length = 32

       # How long to cache unwrapped Project KEKs
       # pkek_cache_ttl = 900

       # Max number of items in pkek cache
       # pkek_cache_limit = 100

       # Secret encryption mechanism (string value)
       # Deprecated group/name - [p11_crypto_plugin]/algorithm
       encryption_mechanism = CKM_AES_CBC

       # HMAC Key Type (string value)
       hmac_key_type=CKK_SHA256_HMAC

       # HMAC Key Generation Mechanism (string value)
       hmac_keygen_mechanism = CKM_NC_SHA256_HMAC_KEY_GEN

       # Generate IVs for CKM_AES_GCM mechanism. (boolean value)
       # Deprecated group/name - [p11_crypto_plugin]/generate_iv
       aes_gcm_generate_iv=True

       # Always set CKA_SENSITIVE=CK_TRUE including
       # CKA_EXTRACTABLE=CK_TRUE keys.
       # default true
       always_set_cka_sensitive=false


The HMAC and MKEK keys can be generated as follows:

    .. code-block:: ini

       barbican-manage hsm gen_hmac \
       --library-path /opt/nfast/toolkits/pkcs11/libcknfast.so \
       --passphrase XXX --slot-id 1 --label thales_hmac_0 \
       --key-type CKK_SHA256_HMAC \
       --mechanism CKM_NC_SHA256_HMAC_KEY_GEN

    .. code-block:: ini

       barbican-manage hsm gen_mkek \
       --library-path /opt/nfast/toolkits/pkcs11/libcknfast.so \
       --passphrase XXX --slot-id 1 --label thales_mkek_0

ATOS Bull
+++++++++

For an ATOS Bull HSM, the plugin configuration looks like:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       # ================= Crypto plugin ===================
       [crypto]
       ..
       enabled_crypto_plugins = p11_crypto

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/usr/lib64/libnethsm.so'

       # Token serial number used to identify the token to be used.  Required
       # when the device has multiple tokens with the same label. (string
       # value)
       token_serial_number = 12345678

       # Token label used to identify the token to be used.  Required when
       # token_serial_number is not specified. (string value)
       #token_label = <None>

       # Password to login to PKCS11 session
       login = 'XXX'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'atos_mkek_0'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'atos_hmac_0'

       # (Optional) HSM Slot ID that contains the token device to be used.
       # (integer value)
       # slot_id = 1

       # Enable Read/Write session with the HSM?
       # rw_session = True

       # Length of Project KEKs to create
       # pkek_length = 32

       # How long to cache unwrapped Project KEKs
       # pkek_cache_ttl = 900

       # Max number of items in pkek cache
       # pkek_cache_limit = 100

       # Secret encryption mechanism (string value)
       # Deprecated group/name - [p11_crypto_plugin]/algorithm
       encryption_mechanism = CKM_AES_CBC

       # HMAC Key Type (string value)
       hmac_key_type = CKK_GENERIC_SECRET

       # HMAC Key Generation Mechanism (string value)
       hmac_keygen_mechanism = CKM_GENERIC_SECRET_KEY_GEN

       # Always set CKA_SENSITIVE=CK_TRUE including
       # CKA_EXTRACTABLE=CK_TRUE keys.
       # default true
       always_set_cka_sensitive=false


The HMAC and MKEK keys can be generated as follows:

    .. code-block:: ini

       barbican-manage hsm gen_hmac --library-path /usr/lib64/libnethsm.so \
       --passphrase XXX --slot-id 1 --label atos_hmac_0 \
       --key-type  CKK_GENERIC_SECRET \
       --mechanism  CKM_GENERIC_SECRET_KEY_GEN

    .. code-block:: ini

       barbican-manage hsm gen_mkek --library-path /usr/lib64/libnethsm.so \
       --passphrase XXX --slot-id 1 --label atos_mkek_0

Utimaco
+++++++

The PKCS#11 plugin configuration looks like:

    .. code-block:: ini

        # ================= Secret Store Plugin ===================
        [secretstore]
        ..
        enabled_secretstore_plugins = store_crypto

        # ================= Crypto plugin ===================
        [crypto]
        ..
        enabled_crypto_plugins = p11_crypto

        [p11_crypto_plugin]
        # Path to vendor PKCS11 library (string value)
        library_path = '/opt/utimaco/lib/libcs_pkcs11_R2.so'

        # Token serial number used to identify the token to be used.  Required
        # when the device has multiple tokens with the same label. (string
        # value)
        token_serial_number = 12345678

        # Token label used to identify the token to be used.  Required when
        # token_serial_number is not specified. (string value)
        #token_label = <None>

        # Password to login to PKCS11 session (string value)
        login = '$up3r$e<retP4ssw0rd'

        # Master KEK label (as stored in the HSM) (string value)
        mkek_label = 'my_mkek'

        # Master KEK length in bytes. (integer value)
        #mkek_length = <None>

        # Master HMAC Key label (as stored in the HSM) (string value)
        hmac_label = 'my_hmac_key'

        # (Optional) HSM Slot ID that contains the token device to be used.
        # (integer value)
        # slot_id = 1

        # Flag for Read/Write Sessions (boolean value)
        #rw_session = true

        # Project KEK length in bytes. (integer value)
        #pkek_length = 32

        # Project KEK Cache Time To Live, in seconds (integer value)
        #pkek_cache_ttl = 900

        # Project KEK Cache Item Limit (integer value)
        #pkek_cache_limit = 100

        # Secret encryption mechanism (string value)
        # Deprecated group/name - [p11_crypto_plugin]/algorithm
        encryption_mechanism = CKM_AES_CBC

        # HMAC Key Type (string value)
        #hmac_key_type = CKK_AES

        # HMAC Key Generation Algorithm (string value)
        #hmac_keygen_mechanism = CKM_AES_KEY_GEN

        # File to pull entropy for seeding RNG (string value)
        #seed_file =

        # Amount of data to read from file for seed (integer value)
        #seed_length = 32

        # User friendly plugin name (string value)
        #plugin_name = PKCS11 HSM

        # Generate IVs for CKM_AES_GCM mechanism. (boolean value)
        # Deprecated group/name - [p11_crypto_plugin]/generate_iv
        #aes_gcm_generate_iv = true

        # HMAC key wrap mechanism
        hmac_keywrap_mechanism = CKM_AES_MAC


The HMAC and MKEK keys can be generated as follows:

    .. code-block:: ini

       barbican-manage hsm gen_mkek --library-path \
       /opt/utimaco/lib/libcs_pkcs11_R2.so --passphrase XXX \
       --slot-id 0 --label 'my_mkek'

    .. code-block:: ini

       barbican-manage hsm gen_hmac --library-path \
       /opt/utimaco/lib/libcs_pkcs11_R2.so --passphrase XXX \
       --slot-id 0 --label 'my_hmac_key'


KMIP Plugin
^^^^^^^^^^^

This secret store plugin is used to communicate with a KMIP device.
The secret is securely stored in the KMIP device directly, rather than in the
Barbican database.  The Barbican database maintains a reference to the
secret's location for later retrieval.

The plugin can be configured to authenticate to the KMIP device using either
a username and password, or using a client certificate.

The configuration for this plugin in ``/etc/barbican/barbican.conf`` is as follows:

    .. code-block:: ini

       [secretstore]
       ..
       enabled_secretstore_plugins = kmip_crypto

       [kmip_plugin]
       username = 'admin'
       password = 'password'
       host = localhost
       port = 5696
       keyfile = '/path/to/certs/cert.key'
       certfile = '/path/to/certs/cert.crt'
       ca_certs = '/path/to/certs/LocalCA.crt'

Dogtag Plugin
^^^^^^^^^^^^^

Dogtag is the upstream project corresponding to the Red Hat Certificate System,
a robust, full-featured PKI solution that contains a Certificate Manager (CA)
and a Key Recovery Authority (KRA) which is used to securely store secrets.

The KRA stores secrets as encrypted blobs in its internal database, with the
master encryption keys being stored either in a software-based NSS security
database, or in a Hardware Security Module (HSM).

Note that the software-based NSS database configuration provides a secure option for
those deployments that do not require or cannot afford an HSM.  This is the only
current plugin to provide this option.

The KRA communicates with HSMs using PKCS#11.  For a list of certified HSMs,
see the latest `release notes <https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/9/html/Release_Notes/>`_.  Dogtag and the KRA meet all the relevant Common Criteria and FIPS specifications.

The KRA is a component of FreeIPA.  Therefore, it is possible to configure the plugin
with a FreeIPA server.  More detailed instructions on how to set up Barbican with FreeIPA
are provided `here <https://vakwetu.wordpress.com/2015/11/30/barbican-and-dogtagipa/>`_.

The plugin communicates with the KRA using a client certificate for a trusted KRA agent.
That certificate is stored in an NSS database as well as a PEM file as seen in the
configuration below.

The configuration for this plugin in ``/etc/barbican/barbican.conf`` is as follows:

    .. code-block:: ini

       [secretstore]
       ..
       enabled_secretstore_plugins = dogtag_crypto

       [dogtag_plugin]
       pem_path = '/etc/barbican/kra_admin_cert.pem'
       dogtag_host = localhost
       dogtag_port = 8443
       nss_db_path = '/etc/barbican/alias'
       nss_password = 'password123'

Vault Plugin
^^^^^^^^^^^^

Vault is a HashiCorp tool for securely accessing secrets and other objects,
such as API keys, passwords, or certificates. Vault provides a unified
interface to any secret, while providing tight access control and recording
a detailed audit log.

The plugin communicates with the Vault using a Vault token.

The configuration for this plugin in ``/etc/barbican/barbican.conf`` is as
follows:

    .. code-block:: ini

       [secretstore]
       ..
       enabled_secretstore_plugins = vault_plugin

       [vault_plugin]
       root_token_id =
       approle_role_id =
       approle_secret_id =
       kv_mountpoint = secret
       vault_url = https://127.0.0.1:8200
       use_ssl = True
       ssl_ca_crt_file = /opt/vault/tls/tls-ca.crt
