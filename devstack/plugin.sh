# Configure the needed tempest options
function configure_barbican_tempest() {
    iniset $TEMPEST_CONFIG service_available barbican True
    roles="$(iniget $TEMPEST_CONFIG auth tempest_roles)"
    if [[ -z $roles ]]; then
        roles="creator"
    else
        roles="$roles,creator"
    fi
    iniset $TEMPEST_CONFIG auth tempest_roles $roles
    iniset $TEMPEST_CONFIG service_available barbican True
}

# check for service enabled
if is_service_enabled barbican; then
    if [[ "$1" == "source" || "`type -t install_barbican`" != 'function' ]]; then
        # Initial source
        source $BARBICAN_DIR/devstack/lib/barbican
    fi

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Barbican"
        stack_install_service barbican
        install_barbicanclient
        if is_service_enabled barbican-pykmip; then
            echo_summary "Installing PyKMIP"
            install_pykmip
        fi
        if is_service_enabled barbican-dogtag; then
            echo_summary "Installing Dogtag"
            install_dogtag_components
        fi
        if is_service_enabled barbican-vault; then
            echo_summary "Installing Vault"
            install_vault
        fi
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring Barbican"
        configure_barbican
        if is_service_enabled barbican-pykmip; then
            echo_summary "Configuring KMIP plugin"
            configure_pykmip
        fi
        if is_service_enabled barbican-dogtag; then
            echo_summary "Configuring Dogtag plugin"
            configure_dogtag_plugin
        fi
        if is_service_enabled barbican-vault; then
            echo_summary "Configuring Vault plugin"
            configure_vault_plugin
        fi

        # Configure Cinder, Nova and Glance to use Barbican
        configure_core_services

        if is_service_enabled key; then
            create_barbican_accounts
        fi
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing Barbican"
        init_barbican
        start_barbican
        if is_service_enabled pykmip-server; then
            echo_summary "Starting PyKMIP server"
            start_pykmip
        fi
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        if is_service_enabled tempest; then
            echo_summary "Configuring Tempest options for Barbican"
            configure_barbican_tempest
        fi
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_barbican
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_barbican
    fi
fi

# Set the correct config options in Nova, Cinder and Glance
function configure_core_services {
    if is_service_enabled n-cpu; then
        iniset $NOVA_CONF key_manager backend 'barbican'
    fi

    if is_service_enabled c-vol; then
        iniset $CINDER_CONF key_manager backend 'barbican'
    fi

    if is_service_enabled g-api; then
        iniset $GLANCE_API_CONF key_manager backend 'barbican'
    fi
}
