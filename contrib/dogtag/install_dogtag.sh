#!/bin/bash

# Copyright 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# install_dogtag.sh
#     Installs a DogTag CA and KRA inside a devstack vm.

function install_389_directory_server {
    # Make sure that 127.0.0.1 resolves to localhost.localdomain (fqdn)
    sed -i "s/^127\.0\.0\.1.*/127\.0\.0\.1\tlocalhost.localdomain localhost/" /etc/hosts

    yum install -y 389-ds-base
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
}

function install_dogtag_ca {
    yum install -y pki-ca
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
}

function wait_for_ca {
    while true; do
        ca_running=$(curl -s -k https://localhost:8373/ca/admin/ca/getStatus | grep -c running)
        if [[ $ca_running == 1 ]]; then
            break
        fi
        sleep 1
    done
}

function install_dogtag_kra {
    yum install -y pki-kra
    mkdir -p /etc/dogtag

    # Even though we are using localhost.localdomain, the server certificate by
    # default will get the real host name for the server. So we need to
    # properly configure the KRA to try to communicate with the real host name
    # instead of the localhost.
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
}


install_389_directory_server
install_dogtag_ca
wait_for_ca
install_dogtag_kra
