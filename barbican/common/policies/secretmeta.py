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


_MEMBER = "role:member"
rules = [
    policy.DocumentedRuleDefault(
        name='secret_meta:get',
        check_str=f'rule:all_but_audit or {_MEMBER}',
        scope_types=['project'],
        description='metadata/: Lists a secrets user-defined metadata. || ' +
                    'metadata/{key}: Retrieves a secrets user-added metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata',
                'method': 'GET'
            },
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:post',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='Adds a new key/value pair to the secrets user-defined ' +
                    'metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:put',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='metadata/: Sets the user-defined metadata for a secret ' +
                    '|| metadata/{key}: Updates an existing key/value pair ' +
                    'in the secrets user-defined metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata',
                'method': 'PUT'
            },
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'PUT'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:delete',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='Delete secret user-defined metadata by key.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'DELETE'
            }
        ]
    ),
]


def list_rules():
    return rules
