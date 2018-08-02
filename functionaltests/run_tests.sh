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

# How many seconds to wait for the API to be responding before giving up
API_RESPONDING_TIMEOUT=20

if ! timeout ${API_RESPONDING_TIMEOUT} sh -c "while ! curl -s http://127.0.0.1/key-manager 2>/dev/null | grep -q 'v1' ; do sleep 1; done"; then
    echo "The Barbican API failed to respond within ${API_RESPONDING_TIMEOUT} seconds"
    exit 1
fi

echo "Successfully contacted the Barbican API"

plugin=$1

if [[ "$plugin" == "kmip" ]]; then
    export KMIP_PLUGIN_ENABLED=1
elif [[ "$plugin" == "vault" ]]; then
    export VAULT_PLUGIN_ENABLED=1
elif [[ "$plugin" == "pkcs11" ]]; then
    export PKCS11_PLUGIN_ENABLED=1
fi

# run the tests sequentially
testr init
testr run --subunit | subunit-trace --no-failure-debug -f
retval=$?
testr slowest

coverage combine
coverage report -m

exit $retval
