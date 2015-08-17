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

echo " OS_SERVICE_ENDPOINT="$OS_SERVICE_ENDPOINT
echo " SERVICE_TOKEN="$OS_SERVICE_TOKEN
echo " OS_TENANT_NAME="$OS_TENANT_NAME
echo " OS_USERNAME="$OS_USERNAME
echo " OS_PASSWORD="$OS_PASSWORD
echo " OS_AUTH_URL="$OS_AUTH_URL

#test with
keystone tenant-list

function get_id {
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
SERVICE_TENANT=$(get_id keystone tenant-create --name="$SERVICE_TENANT_NAME")
ADMIN_ROLE=$(keystone role-list | awk "/ admin / { print \$2 }")
MEMBER_ROLE=$(keystone role-list | awk "/ _member_ / { print \$2 }")

# Ports to avoid: 3333, 5000, 8773, 8774, 8776, 9292, 9696, 35357
# Barbican
if [[ "$ENABLED_SERVICES" =~ "barbican" ]]; then
    #
    # Setup Default Admin User
    #
    BARBICAN_USER=$(get_id keystone user-create \
        --name="barbican" \
        --pass="$SERVICE_PASSWORD" \
        --tenant_id="$SERVICE_TENANT" \
        --email="barbican@example.com")
    keystone user-role-add \
        --tenant_id="$SERVICE_TENANT" \
        --user_id="$BARBICAN_USER" \
        --role_id="$ADMIN_ROLE"
    #
    # Setup Default service-admin User
    #
    SERVICE_ADMIN=$(get_id keystone user-create \
        --name="service-admin" \
        --pass="$SERVICE_PASSWORD" \
        --email="service_admin@example.com")
    SERVICE_ADMIN_ROLE=$(get_id keystone role-create \
        --name="key-manager:service-admin")
    keystone user-role-add \
        --tenant_id="$SERVICE_TENANT" \
        --user_id="$SERVICE_ADMIN" \
        --role_id="$SERVICE_ADMIN_ROLE"
    #
    # Setup RBAC User Projects and Roles
    #
    USER_PASSWORD="barbican"
    PROJECT_A_ID=$(get_id keystone tenant-create \
        --name="project_a")
    PROJECT_B_ID=$(get_id keystone tenant-create \
        --name="project_b")
    ROLE_ADMIN_ID=$(get_id keystone role-get admin)
    ROLE_CREATOR_ID=$(get_id keystone role-create \
        --name="creator")
    ROLE_OBSERVER_ID=$(get_id keystone role-create \
        --name="observer")
    ROLE_AUDIT_ID=$(get_id keystone role-create \
        --name="audit")
    #
    # Setup RBAC Admin of Project A
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_a_admin" \
        --pass="$USER_PASSWORD" \
        --email="admin_a@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_ADMIN_ID" \
        --tenant-id="$PROJECT_A_ID"
    #
    # Setup RBAC Creator of Project A
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_a_creator" \
        --pass="$USER_PASSWORD" \
        --email="creator_a@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_CREATOR_ID" \
        --tenant-id="$PROJECT_A_ID"
    #
    # Setup RBAC Observer of Project A
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_a_observer" \
        --pass="$USER_PASSWORD" \
        --email="observer_a@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_OBSERVER_ID" \
        --tenant-id="$PROJECT_A_ID"
    #
    # Setup RBAC Auditor of Project A
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_a_auditor" \
        --pass="$USER_PASSWORD" \
        --email="auditor_a@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_AUDIT_ID" \
        --tenant-id="$PROJECT_A_ID"
    #
    # Setup RBAC Admin of Project B
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_b_admin" \
        --pass="$USER_PASSWORD" \
        --email="admin_b@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_ADMIN_ID" \
        --tenant-id="$PROJECT_B_ID"

    #
    # Setup RBAC Creator of Project B
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_b_creator" \
        --pass="$USER_PASSWORD" \
        --email="creator_b@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_CREATOR_ID" \
        --tenant-id="$PROJECT_B_ID"

    #
    # Setup RBAC Observer of Project B
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_b_observer" \
        --pass="$USER_PASSWORD" \
        --email="observer_b@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_OBSERVER_ID" \
        --tenant-id="$PROJECT_B_ID"

    #
    # Setup RBAC Auditor of Project B
    #
    USER_ID=$(get_id keystone user-create \
        --name="project_b_auditor" \
        --pass="$USER_PASSWORD" \
        --email="auditor_b@example.net")
    keystone user-role-add \
        --user="$USER_ID" \
        --role="$ROLE_AUDIT_ID" \
        --tenant-id="$PROJECT_B_ID"
    #
    # Setup Admin Endpoint
    #
    if [[ "$KEYSTONE_CATALOG_BACKEND" = 'sql' ]]; then
        BARBICAN_SERVICE=$(get_id keystone service-create \
            --name=barbican \
            --type="key-manager" \
            --description="Barbican Key Management Service")
        keystone endpoint-create \
            --region RegionOne \
            --service_id $BARBICAN_SERVICE \
            --publicurl "http://$SERVICE_HOST:9311" \
            --internalurl "http://$SERVICE_HOST:9311"
    fi
fi
