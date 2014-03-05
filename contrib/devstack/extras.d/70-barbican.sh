#!/bin/sh
# DevStack extras script to install Barbican

if is_service_enabled barbican; then
    if [[ "$1" == "source" ]]; then
        # Initial source
        source $TOP_DIR/lib/barbican
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Barbican"
        install_barbican
        install_barbicanclient
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring Barbican"
        configure_barbican
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
fi
