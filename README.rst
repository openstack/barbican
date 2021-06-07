========================
Team and repository tags
========================


.. image:: https://governance.openstack.org/tc/badges/barbican.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

Barbican
========

Barbican is a REST API designed for the secure storage, provisioning and
management of secrets. It is aimed at being useful for all environments,
including large ephemeral Clouds.

Barbican is an OpenStack project developed by the `Barbican Project Team
<https://wiki.openstack.org/wiki/Barbican>`_ with support from
`Rackspace Hosting <http://www.rackspace.com/`>_, EMC, Ericsson,
Johns Hopkins University, HP, Red Hat, Cisco Systems, and many more.

The full documentation can be found on the `Barbican Developer Documentation
Site <https://docs.openstack.org/barbican/latest/>`_.

To file a bug, use our bug tracker on `OpenStack Storyboard
<https://storyboard.openstack.org/#!/project/980>`_.

Release notes for the project can be found at
https://docs.openstack.org/releasenotes/barbican.

Future design work is tracked at
https://specs.openstack.org/openstack/barbican-specs.

For development questions or discussion, use the `OpenStack-discuss
mailing list <http://lists.openstack.org/pipermail/openstack-discuss/>`_
at `openstack-discuss@lists.openstack.org` and let us know what you
think, just add
`[barbican]` to the subject. You can also join our IRC channel
`#openstack-barbican` on `OFTC <http://oftc.net>`_.

Client Libraries
----------------

* `python-barbicanclient
  <https://opendev.org/openstack/python-barbicanclient>`_ -
  A convenient Python-based library to interact with the Barbican API.

Getting Started
---------------

Please visit our `Users, Developers and Operators documentation
<https://docs.openstack.org/barbican/latest/>`_ for details.

Why Should You Use Barbican?
----------------------------

The current state of key management is atrocious. While Windows does have some
decent options through the use of the Data Protection API (DPAPI) and Active
Directory, Linux lacks a cohesive story around how to manage keys for
application use.

Barbican was designed to solve this problem. The system was motivated by
internal Rackspace needs, requirements from
`OpenStack <http://www.openstack.org/>`_ and a realization that the
current state
of the art could use some help.

Barbican will handle many types of secrets, including:

* **Symmetric Keys** - Used to perform reversible encryption of data at rest,
  typically using the AES algorithm set. This type of key is required to enable
  features like `encrypted Swift containers and Cinder
  volumes <http://www.openstack.org/software/openstack-storage/>`_, `encrypted
  Cloud Backups <http://www.rackspace.com/cloud/backup/>`_, etc.
* **Asymmetric Keys** - Asymmetric key pairs (sometimes referred to as
  `public / private keys
  <http://en.wikipedia.org/wiki/Public-key_cryptography>`_) are used in
  many scenarios where communication between untrusted parties is
  desired. The most common case is with SSL/TLS certificates, but also
  is used in solutions like SSH keys, S/MIME (mail) encryption and
  digital signatures.
* **Raw Secrets** - Barbican stores secrets as a base64 encoded block of data
  (encrypted, naturally). Clients can use the API to store any secrets in any
  format they desire.

For the symmetric and asymmetric key types, Barbican supports full life cycle
management including provisioning, expiration, reporting, etc.

Design Goals
------------

1. Provide a central secret-store capable of distributing secret / keying
   material to all types of deployments including ephemeral Cloud instances.
2. Support reasonable compliance regimes through reporting and auditability.
3. Application adoption costs should be minimal or non-existent.
4. Build a community and ecosystem by being open-source and extensible.
5. Improve security through sane defaults and centralized management
   of `policies for all secrets`.
6. Provide an out of band communication mechanism to notify and protect sensitive
   assets.
