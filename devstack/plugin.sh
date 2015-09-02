# check for service enabled
if is_service_enabled barbican; then
    if [[ "$1" == "source" || "`type -t install_barbican`" != 'function' ]]; then
        # Initial source
        source $BARBICAN_DIR/devstack/lib/barbican
    fi

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Barbican"
        install_barbican
        install_barbicanclient
        if is_service_enabled barbican-dogtag; then
            echo_summary "Installing Dogtag"
            install_dogtag_components
        fi
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring Barbican"
        configure_barbican
        if is_service_enabled barbican-dogtag; then
            echo_summary "Configuring Dogtag plugin"
            configure_dogtag_plugin
        fi
        configure_barbicanclient

        if is_service_enabled key; then
            create_barbican_accounts
        fi
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing Barbican"
        init_barbican
        start_barbican
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_barbican
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_barbican
    fi
fi

