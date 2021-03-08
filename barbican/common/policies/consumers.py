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

# FIXME(hrybacki): Note that the GET rules have the same check strings.
#                  The POST/DELETE rules also share the check stirngs.
#                  These can probably be turned into constants in base


_READER = "role:reader"
_MEMBER = "role:member"
_ADMIN = "role:admin"
_SYSTEM_ADMIN = "role:admin and system_scope:all"
_PROJECT_MEMBER = f"{_MEMBER} and project_id:%(target.container.project_id)s"
_PROJECT_ADMIN = f"{_ADMIN} and project_id:%(target.container.project_id)s"
_CONTAINER_CREATOR = "user_id:%(target.container.creator_id)s"
_CONTAINER_IS_NOT_PRIVATE = "True:%(target.container.read_project_access)s"

rules = [
    policy.DocumentedRuleDefault(
        name='consumer:get',
        check_str='rule:admin or rule:observer or rule:creator or ' +
                  'rule:audit or rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read' +
                  f" or ({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='List a specific consumer for a given container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers/' +
                        '{consumer-id}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='consumers:get',
        check_str='rule:admin or rule:observer or rule:creator or ' +
                  'rule:audit or rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read' +
                  f" or ({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='List a containers consumers.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='consumers:post',
        check_str='rule:admin or rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read' +
                  f" or ({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='Creates a consumer.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='consumers:delete',
        check_str='rule:admin or rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read' +
                  f" or ({_PROJECT_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='Deletes a consumer.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers/' +
                        '{consumer-id}',
                'method': 'DELETE'
            }
        ]
    ),
]


def list_rules():
    return rules
