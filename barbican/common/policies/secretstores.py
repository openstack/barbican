#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_policy import policy


rules = [
    policy.DocumentedRuleDefault(
        name='secretstores:get',
        check_str='rule:admin',
        scope_types=[],
        description='Get list of available secret store backends.',
        operations=[
            {
                'path': '/v1/secret-stores',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secretstores:get_global_default',
        check_str='rule:admin',
        scope_types=[],
        description='Get a reference to the secret store that is used as ' +
                    'default secret store backend for the deployment.',
        operations=[
            {
                'path': '/v1/secret-stores/global-default',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secretstores:get_preferred',
        check_str='rule:admin',
        scope_types=[],
        description='Get a reference to the preferred secret store if ' +
                    'assigned previously.',
        operations=[
            {
                'path': '/v1/secret-stores/preferred',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secretstore_preferred:post',
        check_str='rule:admin',
        scope_types=[],
        description='Set a secret store backend to be preferred store ' +
                    'backend for their project.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}/preferred',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secretstore_preferred:delete',
        check_str='rule:admin',
        scope_types=[],
        description='Remove preferred secret store backend setting for ' +
                    'their project.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}/preferred',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secretstore:get',
        check_str='rule:admin',
        scope_types=[],
        description='Get details of secret store by its ID.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}',
                'method': 'GET'
            }
        ]
    ),
]


def list_rules():
    return rules
