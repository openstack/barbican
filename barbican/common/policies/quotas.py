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
        name='quotas:get',
        check_str='rule:all_users',
        scope_types=[],
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
        check_str='rule:service_admin',
        scope_types=[],
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
        check_str='rule:service_admin',
        scope_types=[],
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
        check_str='rule:service_admin',
        scope_types=[],
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
