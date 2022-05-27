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

# FIXME(hrybacki): Repetitive check strings: Port to simpler checks
#                  - secret_acls:delete, secret_acls:put_patch
#                  - container_acls:delete container_acls:put_patch

_MEMBER = 'role:member'
_ADMIN = 'role:admin'
_SECRET_MEMBER = f"{_MEMBER} and project_id:%(target.secret.project_id)s"
_SECRET_ADMIN = f"{_ADMIN} and project_id:%(target.secret.project_id)s"
_SECRET_CREATOR = "user_id:%(target.secret.creator_id)s"
_SECRET_IS_NOT_PRIVATE = "True:%(target.secret.read_project_access)s"
_CONTAINER_MEMBER = f"{_MEMBER} and project_id:%(target.container.project_id)s"
_CONTAINER_ADMIN = f"{_ADMIN} and project_id:%(target.container.project_id)s"
_CONTAINER_CREATOR = "user_id:%(target.container.creator_id)s"
_CONTAINER_IS_NOT_PRIVATE = "True:%(target.container.read_project_access)s"

rules = [
    policy.DocumentedRuleDefault(
        name='secret_acls:get',
        check_str='(rule:all_but_audit and rule:secret_project_match) or ' +
                  f"({_SECRET_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_SECRET_ADMIN}",
        scope_types=['project'],
        description='Retrieve the ACL settings for a given secret.'
                    'If no ACL is defined for that secret, then Default ACL '
                    'is returned.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'GET'
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_acls:delete',
        check_str='rule:secret_project_admin or rule:secret_project_creator ' +
                  'or (rule:secret_project_creator_role and ' +
                  'rule:secret_non_private_read) or ' +
                  f"({_SECRET_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_SECRET_ADMIN}",
        scope_types=['project'],
        description='Delete the ACL settings for a given secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'DELETE'
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_acls:put_patch',
        check_str='rule:secret_project_admin or rule:secret_project_creator ' +
                  'or (rule:secret_project_creator_role and ' +
                  'rule:secret_non_private_read) or ' +
                  f"({_SECRET_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_SECRET_ADMIN}",
        scope_types=['project'],
        description='Create new, replaces, or updates existing ACL for a ' +
                    'given secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'PUT'
            },
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'PATCH'
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:get',
        check_str='(rule:all_but_audit and rule:container_project_match) or ' +
                  f"({_CONTAINER_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_CONTAINER_ADMIN}",
        scope_types=['project'],
        description='Retrieve the ACL settings for a given container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:delete',
        check_str='rule:container_project_admin or ' +
                  'rule:container_project_creator or ' +
                  '(rule:container_project_creator_role and' +
                  ' rule:container_non_private_read) or ' +
                  f"({_CONTAINER_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_CONTAINER_ADMIN}",
        scope_types=['project'],
        description='Delete ACL for a given container. No content is returned '
                    'in the case of successful deletion.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:put_patch',
        check_str='rule:container_project_admin or ' +
                  'rule:container_project_creator or ' +
                  '(rule:container_project_creator_role and' +
                  ' rule:container_non_private_read) or ' +
                  f"({_CONTAINER_MEMBER} and ({_CONTAINER_CREATOR} or " +
                  f"{_CONTAINER_IS_NOT_PRIVATE})) or {_CONTAINER_ADMIN}",
        scope_types=['project'],
        description='Create new or replaces existing ACL for a given '
                    'container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'PUT'
            },
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'PATCH'
            }
        ]
    ),
]


def list_rules():
    return rules
