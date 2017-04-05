#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside post_test_hook function in devstack gate.

# Install packages from test-requirements.txt

set -ex

plugin=$1

sudo pip install -r /opt/stack/new/barbican/test-requirements.txt

cd /opt/stack/new/barbican/functionaltests
echo 'Running Functional Tests'

if [ "$DEVSTACK_GATE_USE_PYTHON3" = True ]; then
    export PYTHON=$(which python3 2>/dev/null)
fi

sudo -E ./run_tests.sh $plugin
