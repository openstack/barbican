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
_PROJECT_MEMBER = f"{_MEMBER} and project_id:%(target.secret.project_id)s"
_PROJECT_ADMIN = f"{_ADMIN} and project_id:%(target.secret.project_id)s"
_SECRET_CREATOR = "user_id:%(target.secret.creator_id)s"
_SECRET_IS_NOT_PRIVATE = "True:%(target.secret.read_project_access)s"

rules = [
    policy.DocumentedRuleDefault(
        name='secret:decrypt',
        check_str='rule:secret_decrypt_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read or ' +
                  f"({_PROJECT_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
        description='Retrieve a secrets payload.',
        operations=[
            {
                'path': '/v1/secrets/{uuid}/payload',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret:get',
        check_str='rule:secret_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read or ' +
                  f"({_PROJECT_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
        description='Retrieves a secrets metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'GET"'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret:put',
        check_str='rule:admin_or_creator and rule:secret_project_match or ' +
                  f"({_PROJECT_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
        description='Add the payload to an existing metadata-only secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'PUT'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret:delete',
        check_str='rule:secret_project_admin or ' +
                  'rule:secret_project_creator or ' +
                  '(rule:secret_project_creator_role and ' +
                  'not rule:secret_private_read) or ' +
                  f"({_PROJECT_MEMBER} and ({_SECRET_CREATOR} or " +
                  f"{_SECRET_IS_NOT_PRIVATE})) or {_PROJECT_ADMIN}",
        scope_types=['project'],
        description='Delete a secret by uuid.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'DELETE'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secrets:post',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='Creates a Secret entity.',
        operations=[
            {
                'path': '/v1/secrets',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secrets:get',
        check_str=f'rule:all_but_audit or {_MEMBER}',
        scope_types=['project'],
        description='Lists a projects secrets.',
        operations=[
            {
                'path': '/v1/secrets',
                'method': 'GET'
            }
        ]
    )
]


def list_rules():
    return rules
