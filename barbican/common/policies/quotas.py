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


_READER = "role:reader"
_SYSTEM_ADMIN = "role:admin and system_scope:all"
_SYSTEM_READER = "role:reader and system_scope:all"

rules = [
    policy.DocumentedRuleDefault(
        name='quotas:get',
        check_str=f'rule:all_users or {_READER}',
        scope_types=['project'],
        description='List quotas for the project the user belongs to.',
        operations=[
            {
                'path': '/v1/quotas',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:get',
        check_str=f'rule:service_admin or {_SYSTEM_READER}',
        scope_types=['system'],
        description='List quotas for the specified project.',
        operations=[
            {
                'path': '/v1/project-quotas',
                'method': 'GET'
            },
            {
                'path': '/v1/project-quotas/{uuid}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:put',
        check_str=f'rule:service_admin or {_SYSTEM_ADMIN}',
        scope_types=['system'],
        description='Create or update the configured project quotas for '
                    'the project with the specified UUID.',
        operations=[
            {
                'path': '/v1/project-quotas/{uuid}',
                'method': 'PUT'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:delete',
        check_str=f'rule:service_admin or {_SYSTEM_ADMIN}',
        scope_types=['system'],
        description='Delete the project quotas configuration for the '
                    'project with the requested UUID.',
        operations=[
            {
                'path': '/v1/quotas}',
                'method': 'DELETE'
            }
        ]
    ),
]


def list_rules():
    return rules
