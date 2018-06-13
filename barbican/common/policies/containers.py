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
        name='containers:post',
        check_str='rule:admin_or_creator',
        scope_types=[],
        description='Creates a container.',
        operations=[
            {
                'path': '/v1/containers',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='containers:get',
        check_str='rule:all_but_audit',
        scope_types=[],
        description='Lists a projects containers.',
        operations=[
            {
                'path': '/v1/containers',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container:get',
        check_str='rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or ' +
                  'rule:container_acl_read',
        scope_types=[],
        description='Retrieves a single container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container:delete',
        check_str='rule:container_project_admin or ' +
                  'rule:container_project_creator',
        scope_types=[],
        description='Deletes a container.',
        operations=[
            {
                'path': '/v1/containers/{uuid}',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container_secret:post',
        check_str='rule:admin',
        scope_types=[],
        description='Add a secret to an existing container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/secrets',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container_secret:delete',
        check_str='rule:admin',
        scope_types=[],
        description='Remove a secret from a container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/secrets/{secret-id}',
                'method': 'DELETE'
            }
        ]
    ),
]


def list_rules():
    return rules
