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

_SECRET_CREATOR = "user_id:%(target.secret.creator_id)s"
_SECRET_PROJECT = "project_id:%(target.secret.project_id)s"
_SECRET_MEMBER = f"{_MEMBER} and {_SECRET_PROJECT}"
_SECRET_ADMIN = f"{_ADMIN} and {_SECRET_PROJECT}"
_SECRET_ACCESS = (f"{_SECRET_CREATOR} or ({_SECRET_MEMBER} and "
                  f"True:%(target.secret.read_project_access)s)")

_CONTAINER_CREATOR = "user_id:%(target.container.creator_id)s"
_CONTAINER_PROJECT = "project_id:%(target.container.project_id)s"
_CONTAINER_MEMBER = f"{_MEMBER} and {_CONTAINER_PROJECT}"
_CONTAINER_ADMIN = f"{_ADMIN} and {_CONTAINER_PROJECT}"
_CONTAINER_ACCESS = (f"{_CONTAINER_CREATOR} or ({_CONTAINER_MEMBER} and "
                     f"True:%(target.container.read_project_access)s)")

rules = [
    policy.DocumentedRuleDefault(
        name='consumer:get',
        check_str='rule:admin or rule:observer or rule:creator or ' +
                  'rule:audit or rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read' +
                  f" or {_CONTAINER_ACCESS} or {_CONTAINER_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        # This API is unusable.  There is no way for a user to get
        # the consumer-id they would need to send a request.
        description='DEPRECATED: show information for a specific consumer',
        operations=[{
            'path': '/v1/containers/{container-id}/consumers/{consumer-id}',
            'method': 'GET'
        }]
    ),
    policy.DocumentedRuleDefault(
        name='container_consumers:get',
        check_str='rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read ' +
                  f" or {_CONTAINER_ACCESS} or {_CONTAINER_ADMIN} or " +
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
        name='container_consumers:post',
        check_str='rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read ' +
                  f" or {_CONTAINER_ACCESS} or {_CONTAINER_ADMIN} or " +
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
        name='container_consumers:delete',
        check_str='rule:container_non_private_read or ' +
                  'rule:container_project_creator or ' +
                  'rule:container_project_admin or rule:container_acl_read ' +
                  f" or {_CONTAINER_ACCESS} or {_CONTAINER_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='Deletes a consumer.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:get',
        check_str='rule:secret_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read ' +
                  f" or {_SECRET_ACCESS} or {_SECRET_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='List consumers for a secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/consumers',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:post',
        check_str='rule:secret_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read ' +
                  f" or {_SECRET_ACCESS} or {_SECRET_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='Creates a consumer.',
        operations=[
            {
                'path': '/v1/secrets/{secrets-id}/consumers',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:delete',
        check_str='rule:secret_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read ' +
                  f" or {_SECRET_ACCESS} or {_SECRET_ADMIN} or " +
                  f"{_SYSTEM_ADMIN}",
        scope_types=['project', 'system'],
        description='Deletes a consumer.',
        operations=[
            {
                'path': '/v1/secrets/{secrets-id}/consumers',
                'method': 'DELETE'
            }
        ]
    ),
]


def list_rules():
    return rules
