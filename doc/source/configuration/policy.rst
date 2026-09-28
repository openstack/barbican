.. _barbican-policy-generator.conf:

====================
Policy configuration
====================

.. warning::

   JSON formatted policy file is deprecated since Barbican 12.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html

Configuration
~~~~~~~~~~~~~

.. note::

   The auto-generated configuration reference may show the default values of
   ``enforce_new_defaults`` and ``enforce_scope`` as ``True`` (the oslo.policy
   library default). However, Barbican overrides both to ``False`` at runtime.
   To opt in to the new secure RBAC defaults, explicitly set both options to
   ``True`` in the ``[oslo_policy]`` section of ``barbican.conf``.

The following is an overview of all available policies in Barbican. For a sample
configuration file.

.. show-policy::
      :config-file: ../../etc/oslo-config-generator/policy.conf
