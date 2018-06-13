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
        name='transport_key:get',
        check_str='rule:all_users',
        scope_types=[],
        description='Get a specific transport key.',
        operations=[
            {
                'path': '/v1/transport_keys/{key-id}}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='transport_key:delete',
        check_str='rule:admin',
        scope_types=[],
        description='Delete a specific transport key.',
        operations=[
            {
                'path': '/v1/transport_keys/{key-id}',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='transport_keys:get',
        check_str='rule:all_users',
        scope_types=[],
        description='Get a list of all transport keys.',
        operations=[
            {
                'path': '/v1/transport_keys',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='transport_keys:post',
        check_str='rule:admin',
        scope_types=[],
        description='Create a new transport key.',
        operations=[
            {
                'path': '/v1/transport_keys',
                'method': 'POST'
            }
        ]
    ),

]


def list_rules():
    return rules
