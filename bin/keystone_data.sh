#!/bin/bash

#------------------------------------
# the devstack way
# cd <devstack-home>
# source openrc nova service
# This sets up an admin user and the service tenant and passport in environment
#------------------------------------
# alternately export values for
export OS_AUTH_URL="http://localhost:5000/v2.0"
# your secret password
export OS_PASSWORD="password"
export OS_TENANT_NAME="service" 
export OS_USERNAME="nova" 

# --------------------------------
# alternately service_token and endpoint

#export OS_SERVICE_TOKEN=orange
#export OS_SERVICE_ENDPOINT=http://localhost:35357/v2.0
# ========================================

echo " OS_SERVICE_ENDPOINT="$OS_SEVICE_ENDPOINT
echo " SERVICE_TOKEN="$SERVICE_TOKEN
echo " OS_TENANT_NAME="$OS_TENANT_NAME
echo " OS_USERNAME="$OS_USERNAME
echo " OS_PASSWORD="$OS_PASSWORD
echo " OS_AUTH_URL="$OS_AUTH_URL

#test with 
keystone tenant-list 

function get_id () {
    echo `"$@" | awk '/ id / { print $4 }'`
}

#------------------------------------------------------------
# Adding the Key Manager Service: barbican
#------------------------------------------------------------

ENABLED_SERVICES="barbican"
SERVICE_PASSWORD="orange"
SERVICE_HOST="localhost"
SERVICE_TENANT_NAME="service"
KEYSTONE_CATALOG_BACKEND='sql'

#============================
# Lookups
SERVICE_TENANT=$(keystone tenant-list | awk "/ $SERVICE_TENANT_NAME / { print \$2 }")
ADMIN_ROLE=$(keystone role-list | awk "/ admin / { print \$2 }")
MEMBER_ROLE=$(keystone role-list | awk "/ Member / { print \$2 }")

# Ports to avoid: 3333, 5000, 8773, 8774, 8776, 9292, 9696, 35357
# Barbican
if [[ "$ENABLED_SERVICES" =~ "barbican" ]]; then
    BARBICAN_USER=$(get_id keystone user-create \
        --name=barbican \
        --pass="$SERVICE_PASSWORD" \
        --tenant_id $SERVICE_TENANT \
        --email=barbican@example.com)
    keystone user-role-add \
        --tenant_id $SERVICE_TENANT \
        --user_id $BARBICAN_USER \
        --role_id $ADMIN_ROLE
    if [[ "$KEYSTONE_CATALOG_BACKEND" = 'sql' ]]; then
        BARBICAN_SERVICE=$(get_id keystone service-create \
            --name=barbican \
            --type="keystore" \
            --description="Barbican Key Management Service")
        keystone endpoint-create \
            --region RegionOne \
            --service_id $BARBICAN_SERVICE \
            --publicurl "http://$SERVICE_HOST:9311/v1" \
            --adminurl "http://$SERVICE_HOST:9312/v1" \
            --internalurl "http://$SERVICE_HOST:9313/v1"
    fi
fi
