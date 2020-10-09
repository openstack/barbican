Using Secret Store Plugins in Barbican
======================================


Summary
-------

By default, Barbican is configured to use one active secret store plugin in a
deployment. This means that all of the new secrets are going to be stored via
same plugin mechanism (i.e. same storage backend).

In **Newton** OpenStack release, support for configuring multiple secret store
plugin backends is added (`Spec Link`_). As part of this change, client can
choose to select preferred plugin backend for storing their secret at a project
level.


.. _Spec Link: https://review.opendev.org/#/c/263972


Enabling Multiple Barbican Backends
-----------------------------------

Multiple backends support may be needed in specific deployment/ use-case
scenarios and can be enabled via configuration.

For this, a Barbican deployment may have more than one secret storage backend
added in service configuration. Project administrators will have choice of
pre-selecting one backend as the preferred choice for secrets created under
that project. Any **new** secret created under that project will use the
preferred backend to store its key material. When there is no project level
storage backend selected, then new secret will use the global secret storage
backend.

Multiple plugin configuration can be defined as follows.

.. code-block:: ini

    [secretstore]
    # Set to True when multiple plugin backends support is needed
    enable_multiple_secret_stores = True
    stores_lookup_suffix = software, kmip, pkcs11, dogtag, vault

    [secretstore:software]
    secret_store_plugin = store_crypto
    crypto_plugin = simple_crypto

    [secretstore:kmip]
    secret_store_plugin = kmip_plugin
    global_default = True

    [secretstore:dogtag]
    secret_store_plugin = dogtag_plugin

    [secretstore:pkcs11]
    secret_store_plugin = store_crypto
    crypto_plugin = p11_crypto

    [secretstore:vault]
    secret_store_plugin = vault_plugin

When `enable_multiple_secret_stores` is enabled (True), then list property
`stores_lookup_suffix` is used for looking up supported plugin names in
configuration section. This section name is constructed using pattern
'secretstore:{one_of_suffix}'. One of the plugin **must** be explicitly
identified as global default i.e. `global_default = True`. Ordering of suffix
and label used does not matter as long as there is a matching section defined
in service configuration.

.. note::

   For existing Barbican deployment case, its recommended to keep existing
   secretstore and crypto plugin (if applicable) name combination to be used as
   global default secret store. This is needed to be consistent with existing
   behavior.

.. warning::

   When multiple plugins support is enabled, then `enabled_secretstore_plugins`
   and `enabled_crypto_plugins` values are **not** used to instantiate relevant
   plugins. Only above mentioned mechanism is used to identify and instantiate
   store and crypto plugins.

Multiple backend can be useful in following type of usage scenarios.

* In a deployment, a deployer may be okay in storing their dev/test resources
  using a low-security secret store, such as one backend using software-only
  crypto, but may want to use an HSM-backed secret store for production
  resources.
* In a deployment, for certain use cases where a client requires high
  concurrent access of stored keys, HSM might not be a good storage backend.
  Also scaling them horizontally to provide higher scalability is a costly
  approach with respect to database.
* HSM devices generally have limited storage capacity so a deployment will
  have to watch its stored keys size proactively to remain under the limit
  constraint. This is more applicable in KMIP backend than with PKCS11 backend
  because of plugin's different storage approach. This aspect can also result
  from above use case scenario where deployment is storing non-sensitive (from
  dev/test environment) encryption keys in HSM.
* Barbican running as IaaS service or platform component where some class of
  client services have strict compliance requirements (e.g. FIPS) so will use
  HSM backed plugins whereas others may be okay storing keys in software-only
  crypto plugin.
