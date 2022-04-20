.. _verify:

Verify operation
~~~~~~~~~~~~~~~~

Verify operation of the Key Manager (barbican) service.

.. note::

   Perform these commands on the controller node.

#. Install python-barbicanclient package:

   * For openSUSE and SUSE Linux Enterprise:

     .. code-block:: console

        $ zypper install python-barbicanclient

   * For Red Hat Enterprise Linux and CentOS:

     .. code-block:: console

        $ yum install python-barbicanclient

   * For Ubuntu:

     .. code-block:: console

        $ apt-get install python-barbicanclient

#. Source the ``admin`` credentials to be able to perform Barbican
   API calls:

   .. code-block:: console

      $ . admin-openrc

#. Use the OpenStack CLI to store a secret:

   .. code-block:: console

      $ openstack secret store --name mysecret --payload j4=]d21
      +---------------+-----------------------------------------------------------------------+
      | Field         | Value                                                                 |
      +---------------+-----------------------------------------------------------------------+
      | Secret href   | http://10.0.2.15:9311/v1/secrets/655d7d30-c11a-49d9-a0f1-34cdf53a36fa |
      | Name          | mysecret                                                              |
      | Created       | None                                                                  |
      | Status        | None                                                                  |
      | Content types | None                                                                  |
      | Algorithm     | aes                                                                   |
      | Bit length    | 256                                                                   |
      | Secret type   | opaque                                                                |
      | Mode          | cbc                                                                   |
      | Expiration    | None                                                                  |
      +---------------+-----------------------------------------------------------------------+

#. Confirm that the secret was stored by retrieving it:

   .. code-block:: console

      $ openstack secret get http://10.0.2.15:9311/v1/secrets/655d7d30-c11a-49d9-a0f1-34cdf53a36fa
      +---------------+-----------------------------------------------------------------------+
      | Field         | Value                                                                 |
      +---------------+-----------------------------------------------------------------------+
      | Secret href   | http://10.0.2.15:9311/v1/secrets/655d7d30-c11a-49d9-a0f1-34cdf53a36fa |
      | Name          | mysecret                                                              |
      | Created       | 2016-08-16 16:04:10+00:00                                             |
      | Status        | ACTIVE                                                                |
      | Content types | {'default': 'application/octet-stream'}                               |
      | Algorithm     | aes                                                                   |
      | Bit length    | 256                                                                   |
      | Secret type   | opaque                                                                |
      | Mode          | cbc                                                                   |
      | Expiration    | None                                                                  |
      +---------------+-----------------------------------------------------------------------+

   .. note::

      Some items are populated after the secret has been created and will only
      display when retrieving it.

#. Confirm that the secret payload was stored by retrieving it:

   .. code-block:: console

      $ openstack secret get http://10.0.2.15:9311/v1/secrets/655d7d30-c11a-49d9-a0f1-34cdf53a36fa --payload
      +---------+---------+
      | Field   | Value   |
      +---------+---------+
      | Payload | j4=]d21 |
      +---------+---------+
