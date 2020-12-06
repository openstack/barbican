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

The following is an overview of all available policies in Barbican. For a sample
configuration file.

.. show-policy::
      :config-file: ../../etc/oslo-config-generator/policy.conf
