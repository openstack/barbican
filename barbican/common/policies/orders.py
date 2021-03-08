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
        name='orders:get',
        check_str=f'rule:all_but_audit or {_MEMBER}',
        scope_types=['project'],
        description='Gets list of all orders associated with a project.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='orders:post',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='Creates an order.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'POST'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='orders:put',
        check_str=f'rule:admin_or_creator or {_MEMBER}',
        scope_types=['project'],
        description='Unsupported method for the orders API.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'PUT'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='order:get',
        check_str=f'rule:all_users or {_MEMBER}',
        scope_types=['project'],
        description='Retrieves an orders metadata.',
        operations=[
            {
                'path': '/v1/orders/{order-id}',
                'method': 'GET'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name='order:delete',
        check_str=f'rule:admin or {_MEMBER}',
        scope_types=['project'],
        description='Deletes an order.',
        operations=[
            {
                'path': '/v1/orders/{order-id}',
                'method': 'DELETE'
            }
        ],
    )
]


def list_rules():
    return rules
