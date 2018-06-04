#!/bin/bash

#------------------------------------
# the devstack way
# cd <devstack-home>
# source openrc nova service
# This sets up an admin user and the service project and passport in environment
#------------------------------------
# alternately export values for
export OS_AUTH_URL="http://localhost:5000/v2.0"
# your secret password
export OS_PASSWORD="password"
export OS_PROJECT_NAME="service"
export OS_USERNAME="nova"

# --------------------------------
# alternately service_token and endpoint

#export OS_TOKEN=orange
#export OS_URL=http://localhost:5000/v3
# ========================================

echo " OS_URL="$OS_URL
echo " OS_TOKEN="$OS_TOKEN
echo " OS_PROJECT_NAME="$OS_PROJECT_NAME
echo " OS_USERNAME="$OS_USERNAME
echo " OS_PASSWORD="$OS_PASSWORD
echo " OS_AUTH_URL="$OS_AUTH_URL

#test with
openstack project list

#------------------------------------------------------------
# Adding the Key Manager Service: barbican
#------------------------------------------------------------

ENABLED_SERVICES="barbican"
SERVICE_PASSWORD="orange"
SERVICE_HOST="localhost"
SERVICE_PROJECT_NAME="service"
KEYSTONE_CATALOG_BACKEND='sql'

#============================
# Lookups
SERVICE_PROJECT=$(openstack project show "$SERVICE_PROJECT_NAME" -f value -c id)
ADMIN_ROLE=$(openstack role show admin -f value -c id)

# Ports to avoid: 3333, 5000, 8773, 8774, 8776, 9292, 9696
# Barbican
if [[ "$ENABLED_SERVICES" =~ "barbican" ]]; then
    #
    # Setup Default Admin User
    #
    BARBICAN_USER=$(openstack user create \
                                --password "$SERVICE_PASSWORD" \
                                --project $SERVICE_PROJECT \
                                --email "barbican@example.com" \
                                barbican -f value -c id)
    openstack role add --project $SERVICE_PROJECT \
                            --user $BARBICAN_USER \
                            $ADMIN_ROLE
    #
    # Setup Default service-admin User
    #
    SERVICE_ADMIN=$(openstack user create \
        --password "$SERVICE_PASSWORD" \
        --email "service-admin@example.com" \
        "service-admin" -f value -c id)
    SERVICE_ADMIN_ROLE=$(openstack role create \
        "key-manager:service-admin" -f value -c id)
    openstack role add \
        --user "$SERVICE_ADMIN" \
        --project "$SERVICE_PROJECT" \
        "$SERVICE_ADMIN_ROLE"
    #
    # Setup RBAC User Projects and Roles
    #
    PASSWORD="barbican"
    PROJECT_A_ID=$(openstack project create "project_a" -f value -c id)
    PROJECT_B_ID=$(openstack project create "project_b" -f value -c id)
    ROLE_ADMIN_ID=$(openstack role show admin -f value -c id)
    ROLE_CREATOR_ID=$(openstack role create "creator" -f value -c id)
    ROLE_OBSERVER_ID=$(openstack role create "observer" -f value -c id)
    ROLE_AUDIT_ID=$(openstack role create "audit" -f value -c id)
    #
    # Setup RBAC Admin of Project A
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "admin_a@example.net" \
        "project_a_admin" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_A_ID" \
        "$ROLE_ADMIN_ID"
    #
    # Setup RBAC Creator of Project A
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "creator_a@example.net" \
        "project_a_creator" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_A_ID" \
        "$ROLE_CREATOR_ID"
    # Adding second creator user in project_a
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "creator2_a@example.net" \
        "project_a_creator_2" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_A_ID" \
        "$ROLE_CREATOR_ID"
    #
    # Setup RBAC Observer of Project A
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "observer_a@example.net" \
        "project_a_observer" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_A_ID" \
        "$ROLE_OBSERVER_ID"
    #
    # Setup RBAC Auditor of Project A
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "auditor_a@example.net" \
        "project_a_auditor" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_A_ID" \
        "$ROLE_AUDIT_ID"
    #
    # Setup RBAC Admin of Project B
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "admin_b@example.net" \
        "project_b_admin" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_B_ID" \
        "$ROLE_ADMIN_ID"
    #
    # Setup RBAC Creator of Project B
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "creator_b@example.net" \
        "project_b_creator" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_B_ID" \
        "$ROLE_CREATOR_ID"
    #
    # Setup RBAC Observer of Project B
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "observer_b@example.net" \
        "project_b_observer" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_B_ID" \
        "$ROLE_OBSERVER_ID"
    #
    # Setup RBAC auditor of Project B
    #
    USER_ID=$(openstack user create \
        --password "$PASSWORD" \
        --email "auditor_b@example.net" \
        "project_b_auditor" -f value -c id)
    openstack role add \
        --user "$USER_ID" \
        --project "$PROJECT_B_ID" \
        "$ROLE_AUDIT_ID"
    #
    # Setup Barbican Endpoint
    #
    if [[ "$KEYSTONE_CATALOG_BACKEND" = 'sql' ]]; then
        BARBICAN_SERVICE=$(openstack service create \
            --name barbican \
            --description "Barbican Service" \
            'key-manager' -f value -c id)
        openstack endpoint create \
            $BARBICAN_SERVICE \
            --region RegionOne \
            internal "http://$SERVICE_HOST:9311"
        openstack endpoint create \
            $BARBICAN_SERVICE \
            --region RegionOne \
            public "http://$SERVICE_HOST:9311"
    fi
fi
