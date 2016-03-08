***********************************
PKCS11 Key Generation - User Guide
***********************************

The Key Generation script was written with the Deployer in mind. It allows the
deployer to create an MKEK and HMAC signing key for their HSM setup. This
script is intended to be used initially or for key rotation scenarios.

Setup
#####

Initially, the deployer will need to examine the settings in their
`barbican.conf` file under the "Crypto plugin" settings section. Set these
values to whichever defaults you need. This will be used for both the script
and your usage of barbican.

The following items are required to use the PKCS11 plugin:

  * Library Path
  * Login Passphrase (Password to HSM)
  * Slot ID (on HSM)

The following will need to be provided to generate the HMAC and MKEK:
  * MKEK Label
  * MKEK Length
  * HMAC Label


Usage
#####

Viewing the help page can give some awareness to the structure of the script
as well as inform you of any changes.

.. code-block:: bash

    $ pkcs11-key-generation --help

    usage: pkcs11-key-generation [-h] [--library-path LIBRARY_PATH]
                                [--passphrase PASSPHRASE] [--slot-id SLOT_ID]
                                {mkek,hmac} ...

    Barbican MKEK & HMAC Generator

    optional arguments:
      -h, --help            show this help message and exit
      --library-path LIBRARY_PATH
                            Path to vendor PKCS11 library
      --passphrase PASSPHRASE
                            Password to login to PKCS11 session
      --slot-id SLOT_ID     HSM Slot id (Should correspond to a configured PKCS11
                            slot)

    subcommands:
      Action to perform

      {mkek,hmac}
        mkek                Generates a new MKEK.
        hmac                Generates a new HMAC.

**Note:** The user is able to pass the password in as an option or they
can leave the flag out and will be prompted for the password upon submission
of the command.

Generating an MKEK
******************

To generate an MKEK, the user must provide a length and a label for the MKEK.

.. code-block:: bash

    $ pkcs11-key-generation --library-path {library_path here}
    --passphrase {HSM password here} --slot-id {HSM slot here} mkek --length 32
    --label 'HMACLabelHere'
    MKEK successfully generated!


Generating an HMAC
******************

To generate an HMAC, the user must provide a label for the HMAC.

.. code-block:: bash

    $ pkcs11-key-generation --library-path {library_path here}
    --passphrase {HSM password here} --slot-id {HSM slot here} hmac
    --label 'HMACLabelHere'
    HMAC successfully generated!

