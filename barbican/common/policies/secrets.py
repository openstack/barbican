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
        name='secret:decrypt',
        check_str='rule:secret_decrypt_non_private_read or ' +
                  'rule:secret_project_creator or ' +
                  'rule:secret_project_admin or rule:secret_acl_read',
        scope_types=[],
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
                  'rule:secret_project_admin or rule:secret_acl_read',
        scope_types=[],
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
        check_str='rule:admin_or_creator and rule:secret_project_match',
        scope_types=[],
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
                  'rule:secret_project_creator',
        scope_types=[],
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
        check_str='rule:admin_or_creator',
        scope_types=[],
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
        check_str='rule:all_but_audit',
        scope_types=[],
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
