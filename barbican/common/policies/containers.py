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
_MEMBER = "role:member"
_ADMIN = "role:admin"
_PROJECT_MEMBER = f"{_MEMBER} and project_id:%(target.container.project_id)s"
_PROJECT_ADMIN = f"{_ADMIN} and project_id:%(target.container.project_id)s"
_CONTAINER_CREATOR = "user_id:%(target.container.creator_id)s"
_CONTAINER_IS_NOT_PRIVATE = "True:%(target.container.read_project_access)s"

rules = [
    policy.DocumentedRuleDefault(
        name='containers:post',
        check_str=f"rule:admin_or_creator or {_MEMBER}",
        scope_types=['project'],
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
        check_str=f"rule:all_but_audit or {_MEMBER}",
        scope_types=['project'],
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
                  'rule:container_acl_read or ' +
                  f"({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
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
                  'rule:container_project_creator or ' +
                  f"({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
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
        check_str='rule:container_project_admin or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_creator_role and ' +
                  'rule:container_non_private_read or ' +
                  f"({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
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
        check_str='rule:container_project_admin or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_creator_role and ' +
                  'rule:container_non_private_read or ' +
                  f"({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
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
