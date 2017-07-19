#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

set -o errexit

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

source $TOP_DIR/openrc admin admin
source $TOP_DIR/inc/ini-config

set -o xtrace

BARBICAN_USER=barbican_grenade
BARBICAN_PROJECT=barbican_grenade
BARBICAN_PASS=pass

function _barbican_set_user {
    OS_TENANT_NAME=$BARBICAN_PROJECT
    OS_PROJECT_NAME=$BARBICAN_PROJECT
    OS_USERNAME=$BARBICAN_USER
    OS_PASSWORD=$BARBICAN_PASS
}

function create {

    # create a tenant for the server
    eval $(openstack project create -f shell -c id $BARBICAN_PROJECT)
    if [[ -z "$id" ]]; then
        die $LINENO "Didn't create $BARBICAN_PROJECT project"
    fi
    resource_save barbican project_id $id
    local project_id=$id

    # create the user, and set $id locally
    eval $(openstack user create $BARBICAN_USER \
        --project $id \
        --password $BARBICAN_PASS \
        -f shell -c id)
    if [[ -z "$id" ]]; then
        die $LINENO "Didn't create $BARBICAN_USER user"
    fi
    resource_save barbican user_id $id
    openstack role add admin --user $id --project $project_id
    _barbican_set_user

    local secret_name=test_secret
    local secret_data=this_is_a_secret_data
    openstack secret store -p $secret_data -n $secret_name
    secret_link=$(openstack secret list | awk '/ test_secret / {print $2}')
    resource_save barbican secret_link $secret_link
}

function verify {
    _barbican_set_user
    secret_link=$(resource_get barbican secret_link)
    openstack secret get $secret_link
}

function verify_noapi {
    :
}

function destroy {
    _barbican_set_user
    set +o errexit
    openstack secret delete $(resource_get barbican secret_link)
    local user_id=$(resource_get barbican user_id)
    local project_id=$(resource_get barbican project_id)
    source $TOP_DIR/openrc admin admin
    openstack user delete $user_id
    openstack project delete $project_id
}

# Dispatcher
case $1 in
    "create")
    create
    ;;
    "verify")
    verify
    ;;
    "verify_noapi")
    verify_noapi
    ;;
    "destroy")
    destroy
    ;;
esac