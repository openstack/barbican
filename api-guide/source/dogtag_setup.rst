**************************
Dogtag Setup - User Guide
**************************

Dogtag is the Open Source upstream community version of the Red Hat Certificate
System, an enterprise certificate management system that has been deployed in some
of the largest PKI deployments worldwide.  RHCS is FIPS 140-2 and Common Criteria certified.

The Dogtag Certificate Authority (CA) subsystem issues, renews and revokes many different
kinds of certificates.  It can be used as a private CA back-end to barbican, and interacts
with barbican through the Dogtag CA plugin.

The Dogtag KRA subsystem is used to securely store secrets after being encrypted by
storage keys that are stored either in a software NSS database or in an HSM.  It
can serve as a secret store for barbican, and interacts with barbican core through
the Dogtag KRA plugin.

In this guide, we will provide instructions on how to set up a basic Dogtag instance
containing a CA and a KRA, and how to configure barbican to use this instance for a
secret store and a certificate plugin.  Much more detail about Dogtag, its deployment
options and its administration are available in the `RHCS documentation
<https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System>`_.

**Note:** The code below is taken from the devstack Barbican-Dogtag gate job.  You can
extract this code by looking at the Dogtag functions in contrib/devstack/lib/barbican.

Installing the Dogtag Packages
******************************

Dogtag packages are available in Fedora/RHEL/Centos and on Ubuntu/Debian distributions.
This guide will include instructions applicable to Fedora/RHEL/Centos.

If installing on a Fedora platform, use at least Fedora 21.
To install the required packages:

.. code-block:: bash

    yum install -y pki-ca pki-kra 389-ds-base

Creating the Directory Server Instance for the Dogtag Internal DB
*****************************************************************

The Dogtag CA and KRA subsystems use a 389 directory server as an internal database.
Configure one as follows:

.. code-block:: bash

    mkdir -p /etc/389-ds

    cat > /etc/389-ds/setup.inf <<EOF

    [General]
    FullMachineName= localhost.localdomain
    SuiteSpotUserID= nobody
    SuiteSpotGroup= nobody

    [slapd]
    ServerPort= 389
    ServerIdentifier= pki-tomcat
    Suffix= dc=example,dc=com
    RootDN= cn=Directory Manager
    RootDNPwd= PASSWORD
    EOF

    setup-ds.pl --silent --file=/etc/389-ds/setup.inf

Creating the Dogtag CA
**********************

The following bash code sets up a Dogtag CA using some reasonable defaults to run in
an Apache Tomcat instance on ports 8373 and 8370.  Detailed version-specific documentation
is packaged and installed with the Dogtag packages as Linux man pages.  For more
details on how to customize a Dogtag instance, see the man pages for *pkispawn* or
consult the `RHCS documentation <https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System>`_.

.. code-block:: bash

    mkdir -p /etc/dogtag

    cat > /etc/dogtag/ca.cfg <<EOF

    [CA]
    pki_admin_email=caadmin@example.com
    pki_admin_name=caadmin
    pki_admin_nickname=caadmin
    pki_admin_password=PASSWORD
    pki_admin_uid=caadmin
    pki_backup_password=PASSWORD
    pki_client_database_password=PASSWORD
    pki_client_database_purge=False
    pki_client_pkcs12_password=PASSWORD
    pki_clone_pkcs12_password=PASSWORD
    pki_ds_base_dn=dc=ca,dc=example,dc=com
    pki_ds_database=ca
    pki_ds_password=PASSWORD
    pki_security_domain_name=EXAMPLE
    pki_token_password=PASSWORD
    pki_https_port=8373
    pki_http_port=8370
    pki_ajp_port=8379
    pki_tomcat_server_port=8375
    EOF

    pkispawn -v -f /etc/dogtag/ca.cfg -s CA

Creating the Dogtag KRA
***********************

The following bash code sets up the Dogtag KRA in the same Apache Tomcat instance
as above.  In this simple example, it is required to set up the CA even if only
the KRA is being used for a secret store.

Note that the actual hostname of the machine should be used in the script (rather
than localhost) because the hostname is used in the subject name for the SSL
server certificate for the KRA.

.. code-block:: bash

    mkdir -p /etc/dogtag

    hostname=$(hostname)
    cat > /etc/dogtag/kra.cfg <<EOF

    [KRA]
    pki_admin_cert_file=/root/.dogtag/pki-tomcat/ca_admin.cert
    pki_admin_email=kraadmin@example.com
    pki_admin_name=kraadmin
    pki_admin_nickname=kraadmin
    pki_admin_password=PASSWORD
    pki_admin_uid=kraadmin
    pki_backup_password=PASSWORD
    pki_client_database_password=PASSWORD
    pki_client_database_purge=False
    pki_client_pkcs12_password=PASSWORD
    pki_clone_pkcs12_password=PASSWORD
    pki_ds_base_dn=dc=kra,dc=example,dc=com
    pki_ds_database=kra
    pki_ds_password=PASSWORD
    pki_security_domain_name=EXAMPLE
    pki_security_domain_user=caadmin
    pki_security_domain_password=PASSWORD
    pki_token_password=PASSWORD
    pki_https_port=8373
    pki_http_port=8370
    pki_ajp_port=8379
    pki_tomcat_server_port=8375
    pki_security_domain_hostname=$hostname
    pki_security_domain_https_port=8373
    EOF

    pkispawn -v -f /etc/dogtag/kra.cfg -s KRA

Configuring Barbican to Communicate with the Dogtag CA and KRA
**************************************************************

In order for barbican to interact with the Dogtag CA and KRA, a PEM file must be
created with trusted agent credentials.

.. code-block:: bash

    PASSWORD=password
    USER=barbican
    BARBICAN_CONF_DIR=/etc/barbican
    openssl pkcs12 -in /root/.dogtag/pki-tomcat/ca_admin_cert.p12 -passin pass:PASSWORD \
        -out $BARBICAN_CONF_DIR/kra_admin_cert.pem -nodes
    chown $USER $BARBICAN_CONF_DIR/kra_admin_cert.pem

The barbican config file (/etc/barbican/barbican.conf) needs to be modified.
The modifications below set the Dogtag plugins as the only enabled secret store and
certificate plugins.  Be sure to restart barbican once these changes are made.

Note that the actual hostname of the machine should be used in the script (rather
than localhost) because the hostname is used in the subject name for the SSL
server certificate for the CA.

.. code-block:: bash

    [dogtag_plugin]
    pem_path = '/etc/barbican/kra_admin_cert.pem'
    dogtag_host = $(hostname)
    dogtag_port = 8373
    nss_db_path = '/etc/barbican/alias'
    nss_db_path_ca = '/etc/barbican/alias-ca'
    nss_password = 'password'
    simple_cmc_profile = 'caOtherCert'
    approved_profile_list = 'caServerCert'

    [secretstore]
    namespace = barbican.secretstore.plugin
    enabled_secretstore_plugins = dogtag_crypto

    [certificate]
    namespace = barbican.certificate.plugin
    enabled_certificate_plugins = dogtag


Testing the Setup
*****************

Once all the above is set up, you can test the CA and KRA plugins by making a
request for a certificate using a pre-approved profile.  As the issued certs are
stored in the secret_store, this indirectly tests the KRA plugin as well.

First, follow the instructions in :ref:`finding_the_cas` to find the ca_id of
the Dogtag CA.

Second, submit a simple CMC request as detailed in :ref:`simple_cmc_order`.

The request should be automatically approved, and you should be able to extract
the certificate from the certificate container in the order.
