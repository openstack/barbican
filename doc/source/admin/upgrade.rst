=================================
Key Manager Service Upgrade Guide
=================================

This document outlines several steps and notes for operators to reference
when upgrading their barbican from previous versions of OpenStack.

Plan to Upgrade
===============

* The `release notes <https://docs.openstack.org/releasenotes/barbican/>`_
  should be read carefully before upgrading the barbican services.
  Starting with the Mitaka release, specific upgrade steps and considerations
  are well-documented in the release notes.

* Upgrades are only supported between sequential releases.

* When upgrading barbican, the following steps should be followed:

  #. Destroy all barbican services

  #. Upgrade source code to the next release

  #. Upgrade barbican database to the next release

      .. code-block:: bash

        barbican-db-manage upgrade

  #. Start barbican services


Upgrade from Newton to Ocata
============================

The barbican-api-paste.ini configuration file for the paste pipeline was
updated to add the http_proxy_to_wsgi middleware. It can be used to help
barbican respond with the correct URL refs when it's put behind a TLS proxy
(such as HAProxy). This middleware is disabled by default, but can be enabled
via a configuration option in the oslo_middleware group.

See `Ocata release notes <https://docs.openstack.org/releasenotes/barbican/ocata.html#upgrade-notes>`_.


Upgrade from Mitaka to Newton
=============================

There are no extra instructions that should be noted for this upgrade.

See `Newton release notes <https://docs.openstack.org/releasenotes/barbican/newton.html>`_.


Upgrade from Liberty to Mitaka
==============================

The Metadata API requires an update to the Database Schema. Existing
deployments that are being upgraded to Mitaka should use the ‘barbican-manage'
utility to update the schema.

If you are upgrading from previous version of barbican that uses the PKCS#11
Cryptographic Plugin driver, you will need to run the migration script.

    .. code-block:: bash

      python barbican/cmd/pkcs11_migrate_kek_signatures.py

See `Mitaka release notes <https://docs.openstack.org/releasenotes/barbican/mitaka.html#upgrade-notes>`_.

