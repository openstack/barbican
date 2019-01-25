.. _barbican_backend:

Secret Store Back-ends
~~~~~~~~~~~~~~~~~~~~~~

The Key Manager service has a plugin architecture that allows the deployer to
store secrets in one or more secret stores.  Secret stores can be software-based
such as a software token,  or hardware devices such as a hardware security
module (HSM).

This section describes the plugins that are currently available
and how they might be configured.

Crypto Plugins
--------------

These types of plugins store secrets as encrypted blobs within the
Barbican database.  The plugin is invoked to encrypt the secret on secret
storage, and decrypt the secret on secret retrieval.

To enable these plugins, add ``store_crypto`` to the list of enabled
secret store plugins in the ``[secret_store]`` section of
``/etc/barbican/barbican.conf`` :

    .. code-block:: ini

       [secretstore]
       namespace = barbican.secretstore.plugin
       enabled_secretstore_plugins = store_crypto

There are two flavors of storage plugins currently available: the Simple
Crypto plugin and the PKCS#11 crypto plugin.

Simple Crypto Plugin
^^^^^^^^^^^^^^^^^^^^

This crypto plugin is configured by default in ``/etc/barbican/barbican.conf``.  This plugin
is completely insecure and is only suitable for development testing.

This plugin uses single symmetric key (kek - or 'key encryption key')
- which is stored in plain text in the ``/etc/barbican/barbican.conf`` file to encrypt
and decrypt all secrets.

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

PKCS#11 Crypto Plugin
^^^^^^^^^^^^^^^^^^^^^

This crypto plugin can be used to interface with a Hardware Security Module (HSM)
using the PKCS#11 protocol.

Secrets are encrypted (and decrypted on retrieval) by a project specific
Key Encryption Key (KEK), which resides in the HSM.

The configuration for this plugin in ``/etc/barbican/barbican.conf``.
Settings for some different HSMs are provided below:

Safenet
+++++++

The PKCS#11 plugin configuration looks like:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/usr/lib/libCryptoki2_64.so'

       # Password to login to PKCS11 session
       login = 'mypassword'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'an_mkek'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'my_hmac_label'

       # HSM Slot id (Should correspond to a configured PKCS11 slot). Default: 1
       # slot_id = 1

       # Enable Read/Write session with the HSM?
       # rw_session = True

       # Length of Project KEKs to create
       # pkek_length = 32

       # How long to cache unwrapped Project KEKs
       # pkek_cache_ttl = 900

       # Max number of items in pkek cache
       # pkek_cache_limit = 100

Thales
++++++

For a Thales NetHSM, the plugin configuration looks like:

    .. code-block:: ini

       # ================= Secret Store Plugin ===================
       [secretstore]
       ..
       enabled_secretstore_plugins = store_crypto

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/opt/nfast/toolkits/pkcs11/libcknfast.so'

       # Password to login to PKCS11 session
       login = 'XXX'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'thales_mkek_0'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'thales_hmac_0'

       # HSM Slot id (Should correspond to a configured PKCS11 slot). Default: 1
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

       [p11_crypto_plugin]
       # Path to vendor PKCS11 library
       library_path = '/usr/lib64/libnethsm.so'

       # Password to login to PKCS11 session
       login = 'XXX'

       # Label to identify master KEK in the HSM (must not be the same as HMAC label)
       mkek_label = 'atos_mkek_0'

       # Length in bytes of master KEK
       mkek_length = 32

       # Label to identify HMAC key in the HSM (must not be the same as MKEK label)
       hmac_label = 'atos_hmac_0'

       # HSM Slot id (Should correspond to a configured PKCS11 slot). Default: 1
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


KMIP Plugin
-----------

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
-------------

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
