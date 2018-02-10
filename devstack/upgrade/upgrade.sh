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
#
# ``upgrade-barbican``

echo "*********************************************************************"
echo "Begin $0"
echo "*********************************************************************"

cleanup() {
    set +o errexit

        echo "*********************************************************************"
    echo "ERROR: Abort $0"
        echo "*********************************************************************"

    # Kill ourselves to signal any calling process
        trap 2; kill -2 $$
}
trap cleanup SIGHUP SIGINT SIGTERM

# Keep track of the grenade directory
RUN_DIR=$(cd $(dirname "$0") && pwd)

# Source params
source $GRENADE_DIR/grenaderc

# Import common functions
source $GRENADE_DIR/functions

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Upgrade barbican
# Get functions from current DevStack
source $TARGET_DEVSTACK_DIR/stackrc
source $TARGET_DEVSTACK_DIR/lib/tls
source $(dirname $(dirname $BASH_SOURCE))/plugin.sh
source $(dirname $(dirname $BASH_SOURCE))/settings

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace

# Save current config files for posterity
[[ -d $SAVE_DIR/etc.barbican ]] || cp -pr $BARBICAN_CONF_DIR $SAVE_DIR/etc.barbican

git_clone $BARBICAN_REPO $BARBICAN_DIR $BARBICAN_BRANCH
setup_develop $BARBICAN_DIR

# calls upgrade-barbican for specific release
upgrade_project barbican $RUN_DIR $BASE_DEVSTACK_BRANCH $TARGET_DEVSTACK_BRANCH

$BARBICAN_BIN_DIR/barbican-manage db upgrade -v head || die $LINENO "DB sync error"

# Start the Barbican service up.
run_process barbican-svc "$BARBICAN_BIN_DIR/uwsgi --ini $BARBICAN_UWSGI_CONF"
sleep 10
run_process barbican-retry "$BARBICAN_BIN_DIR/barbican-retry --config-file=$BARBICAN_CONF_DIR/barbican.conf"
