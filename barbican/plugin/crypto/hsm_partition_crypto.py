from oslo_config import cfg

from barbican import i18n as u
from barbican.common import config, exception, utils
from barbican.model import repositories
from barbican.plugin.crypto import base as c
from barbican.plugin.crypto import p11_crypto

LOG = utils.getLogger(__name__)
CONF = config.new_config()

# Register hsm partition plugin options
hsm_partition_crypto_plugin_group = cfg.OptGroup(
    name="hsm_partition_crypto_plugin", title="HSM Partition Crypto Plugin Options"
)
hsm_partition_crypto_plugin_opts = [
    cfg.StrOpt(
        "plugin_name",
        help=u._("User friendly plugin name"),
        default="HSM Partition Crypto Plugin",
    ),
    cfg.StrOpt(
        "default_partition_id",
        help=u._("Default HSM partition ID if no project mapping exists"),
        default=None,
    ),
    cfg.StrOpt("mkek_label", help=u._("Master KEK label (as stored in the HSM)")),
    cfg.IntOpt(
        "mkek_length", default=32, min=1, help=u._("Master KEK length in bytes.")
    ),
    cfg.StrOpt("hmac_label", help=u._("Master HMAC Key label (as stored in the HSM)")),
    cfg.BoolOpt("rw_session", help=u._("Flag for Read/Write Sessions"), default=True),
    cfg.IntOpt("pkek_length", help=u._("Project KEK length in bytes."), default=32),
    cfg.IntOpt(
        "pkek_cache_ttl",
        help=u._("Project KEK Cache Time To Live, in seconds"),
        default=900,
    ),
    cfg.IntOpt(
        "pkek_cache_limit", help=u._("Project KEK Cache Item Limit"), default=100
    ),
    cfg.StrOpt(
        "encryption_mechanism",
        help=u._("Secret encryption mechanism"),
        default="CKM_AES_CBC",
        deprecated_name="algorithm",
    ),
    cfg.StrOpt("hmac_key_type", help=u._("HMAC Key Type"), default="CKK_AES"),
    cfg.StrOpt(
        "hmac_keygen_mechanism",
        help=u._("HMAC Key Generation Algorithm used to create the master HMAC Key."),
        default="CKM_AES_KEY_GEN",
    ),
    cfg.StrOpt(
        "hmac_mechanism",
        help=u._("HMAC algorithm used to sign encrypted data."),
        default="CKM_SHA256_HMAC",
        deprecated_name="hmac_keywrap_mechanism",
    ),
    cfg.StrOpt(
        "key_wrap_mechanism",
        help=u._("Key Wrapping algorithm used to wrap Project KEKs."),
        default="CKM_AES_CBC_PAD",
    ),
    cfg.BoolOpt(
        "key_wrap_generate_iv",
        help=u._("Generate IVs for Key Wrapping mechanism."),
        default=True,
    ),
    cfg.StrOpt(
        "seed_file", help=u._("File to pull entropy for seeding RNG"), default=""
    ),
    cfg.IntOpt(
        "seed_length", help=u._("Amount of data to read from file for seed"), default=32
    ),
    cfg.BoolOpt(
        "aes_gcm_generate_iv",
        help=u._("Generate IVs for CKM_AES_GCM mechanism."),
        default=True,
        deprecated_name="generate_iv",
    ),
    cfg.BoolOpt(
        "always_set_cka_sensitive",
        help=u._(
            "Always set CKA_SENSITIVE=CK_TRUE including CKA_EXTRACTABLE=CK_TRUE keys."
        ),
        default=True,
    ),
    cfg.BoolOpt(
        "os_locking_ok",
        help=u._(
            "Enable CKF_OS_LOCKING_OK flag when initializing the "
            "PKCS#11 client library."
        ),
        default=False,
    ),
]


# Register Vendor-specific sections
def register_hsm_vendor_sections():
    # Define vendor HSMs that you want to support
    vendors = ["thales_hsm", "utimaco_hsm"]

    for vendor in vendors:
        # Construct the section name
        section_name = f"hsm_partition_crypto_plugin:{vendor}"

        # Create a new option group for the vendor
        vendor_group = cfg.OptGroup(
            name=section_name, title=f"HSM Partition Crypto Plugin Options for {vendor}"
        )

        # Register the group and options
        CONF.register_group(vendor_group)
        CONF.register_opts(hsm_partition_crypto_plugin_opts, group=vendor_group)

        LOG.debug(f"Registered HSM vendor configuration section: {section_name}")


# Register all vendor sections
register_hsm_vendor_sections()

CONF.register_group(hsm_partition_crypto_plugin_group)
CONF.register_opts(
    hsm_partition_crypto_plugin_opts, group=hsm_partition_crypto_plugin_group
)
config.parse_args(CONF)


def list_opts():
    yield hsm_partition_crypto_plugin_group, hsm_partition_crypto_plugin_opts


class HSMPartitionCryptoPlugin(p11_crypto.P11CryptoPlugin):
    """PKCS11 crypto plugin for HSMaaS. Inherits from P11CryptoPlugin

    This plugin extends the base PKCS11 plugin to support per-project HSM
    partitions. Each project is mapped to its own HSM partition with isolated
    keys and credentials.
    """

    def __init__(self, conf=None, ffi=None, pkcs11=None, store_plugin_name=None):
        """Initialize plugin using dynamic config based on secret store name."""

        # Use the global CONF if none provided
        if conf is None:
            conf = CONF

        # Store name of the secret store that uses this plugin
        self.store_plugin_name = store_plugin_name or "default"

        # Build section name based on secret store
        self.section_name = f"hsm_partition_crypto_plugin:{self.store_plugin_name}"

        # If this is a default instance (no specific store), use base config
        if self.store_plugin_name == "default":
            self.section_name = "hsm_partition_crypto_plugin"

        # Make sure PKCS11 object is available
        self.pkcs11 = None

        # Get config for this section
        try:
            self.conf = conf[self.section_name]
            LOG.info(f"Using HSM configuration section: {self.section_name}")
        except KeyError:
            # Section doesn't exist - either create dynamically or use base
            if self.store_plugin_name != "default":
                LOG.warning(
                    f"No config found for {self.section_name}, registering dynamically"
                )
                group = cfg.OptGroup(
                    name=self.section_name,
                    title=f"HSM Partition Crypto Plugin Options for {self.store_plugin_name}",
                )
                conf.register_group(group)
                conf.register_opts(hsm_partition_crypto_plugin_opts, group=group)
                self.conf = conf[self.section_name]
            else:
                LOG.warning("Using default HSM configuration section")
                self.conf = conf["hsm_partition_crypto_plugin"]

        # Initialize basic attributes from config
        self.library_path = None
        self.login = None
        self.rw_session = self.conf.rw_session
        self.slot_id = None
        self.token_labels = None
        self.token_serial_number = None
        self.seed_file = self.conf.seed_file
        self.seed_length = self.conf.seed_length

        # Crypto configuration
        self.encryption_mechanism = self.conf.encryption_mechanism
        self.encryption_gen_iv = self.conf.aes_gcm_generate_iv
        self.cka_sensitive = self.conf.always_set_cka_sensitive
        self.mkek_key_type = "CKK_AES"  # Optional: make configurable
        self.mkek_length = self.conf.mkek_length
        self.mkek_label = self.conf.mkek_label
        self.hmac_key_type = self.conf.hmac_key_type
        self.hmac_label = self.conf.hmac_label
        self.hmac_mechanism = self.conf.hmac_mechanism
        self.key_wrap_mechanism = self.conf.key_wrap_mechanism
        self.key_wrap_gen_iv = self.conf.key_wrap_generate_iv
        self.os_locking_ok = self.conf.os_locking_ok
        self.pkek_length = self.conf.pkek_length
        self.pkek_cache_ttl = self.conf.pkek_cache_ttl
        self.pkek_cache_limit = self.conf.pkek_cache_limit

        # Initialize repository interfaces
        self.hsm_partition_repo = repositories.get_hsm_partition_repository()
        self.project_hsm_repo = repositories.get_project_hsm_repository()

        # Runtime variables
        self.current_project_id = None
        self.current_partition = None

    def _get_partition_for_project(self, project_id):
        """Get HSM partition configuration for a project."""
        if not project_id:
            raise ValueError(u._("Project ID is required"))

        # Check for project-specific mapping
        try:
            proj_mapping = self.project_hsm_repo.get_by_project_id(project_id)
            return self.hsm_partition_repo.get_by_id(proj_mapping.partition_id)
        except Exception as e:
            LOG.warning(f"Error finding default partition: {e}, {type(e).__name__}")

        # Fall back to default if configured
        if self.conf.default_partition_id:
            try:
                return self.hsm_partition_repo.get_by_id(self.conf.default_partition_id)
            except exception.NotFound:
                LOG.warning(
                    f"Default partition ID {self.conf.default_partition_id} not found"
                )
                pass

        # Nothing found
        raise ValueError(
            u._(
                "No HSM partition mapping found for project and no valid default configured"
            )
        )

    def _configure_pkcs11(self, project_id):
        """Configure PKCS11 for the specified project if needed."""

        # If we're already configured for this project, do nothing
        if project_id == self.current_project_id and self.pkcs11 is not None:
            return

        # Get partition config for the project
        partition = self._get_partition_for_project(project_id)
        if not partition:
            raise ValueError(u._("No HSM partition mapping found for project"))

        # Store current project and partition
        self.current_project_id = project_id
        self.current_partition = partition

        # Set required attributes for parent class
        self.library_path = partition.credentials["library_path"]
        self.login = partition.credentials["password"]
        self.slot_id = int(partition.slot_id)
        self.token_labels = [partition.token_label] if partition.token_label else None

        # Create new PKCS11 instance
        self.pkcs11 = self._create_pkcs11(None)
        self._configure_object_cache()

    def get_plugin_name(self):
        """Gets user friendly plugin name."""
        return self.conf.plugin_name

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        self._configure_pkcs11(project_id)
        return super(HSMPartitionCryptoPlugin, self).encrypt(
            encrypt_dto, kek_meta_dto, project_id
        )

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended, project_id):
        self._configure_pkcs11(project_id)
        return super(HSMPartitionCryptoPlugin, self).decrypt(
            decrypt_dto, kek_meta_dto, kek_meta_extended, project_id
        )

    def bind_kek_metadata(self, kek_meta_dto):
        # Extract project_id from the kek_meta_dto
        if hasattr(kek_meta_dto, "project_id"):
            project_id = kek_meta_dto.project_id
        else:
            # For the bind_kek_metadata case, get project_id from kek_label
            # The format is "project-{external_id}-key-{uuid}"
            try:
                label_parts = kek_meta_dto.kek_label.split("-")
                if len(label_parts) >= 4 and label_parts[0] == "project":
                    project_id = label_parts[1]
                else:
                    # If we can't determine project_id, use default partition
                    LOG.warning(
                        "Cannot determine project_id from kek_label: %s, using default partition",
                        kek_meta_dto.kek_label,
                    )
                    project_id = None
            except (AttributeError, IndexError):
                LOG.warning("Invalid kek_label format, using default partition")
                project_id = None

        self._configure_pkcs11(project_id)
        return super(HSMPartitionCryptoPlugin, self).bind_kek_metadata(kek_meta_dto)

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        self._configure_pkcs11(project_id)
        return super(HSMPartitionCryptoPlugin, self).generate_symmetric(
            generate_dto, kek_meta_dto, project_id
        )


class UtimacoHSMPartitionCryptoPlugin(HSMPartitionCryptoPlugin):
    """Utimaco HSM Partition Crypto Plugin.

    This is a specialized version of HSMPartitionCryptoPlugin configured
    for Utimaco HSMs. It uses the hsm_partition_crypto_plugin:utimaco_hsm
    configuration section.
    """

    def __init__(self, *args, **kwargs):
        """Initialize with the utimaco_hsm store plugin name."""
        kwargs["store_plugin_name"] = "utimaco_hsm"
        super(UtimacoHSMPartitionCryptoPlugin, self).__init__(*args, **kwargs)


class ThalesHSMPartitionCryptoPlugin(HSMPartitionCryptoPlugin):
    """Thales HSM Partition Crypto Plugin.

    This is a specialized version of HSMPartitionCryptoPlugin configured
    for Thales HSMs. It uses the hsm_partition_crypto_plugin:thales_hsm
    configuration section.
    """

    def __init__(self, *args, **kwargs):
        """Initialize with the utimaco_hsm store plugin name."""
        kwargs["store_plugin_name"] = "thales_hsm"
        super(ThalesHSMPartitionCryptoPlugin, self).__init__(*args, **kwargs)
