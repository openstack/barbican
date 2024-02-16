# For more information on Devstack plugins, including a more detailed
# explanation on when the different steps are executed please see:
# https://docs.openstack.org/devstack/latest/plugins.html

BARBICAN_PLUGIN=$DEST/barbican/devstack
source $BARBICAN_PLUGIN/lib/barbican

if is_service_enabled barbican; then
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
            create_barbican_endpoints
            if [[ "$BARBICAN_ENFORCE_SCOPE" == "False" ]]; then
                create_deprecated_rbac_accounts
            fi
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
            source $BARBICAN_PLUGIN/lib/tempest
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
