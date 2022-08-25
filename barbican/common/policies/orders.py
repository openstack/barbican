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

from oslo_log import versionutils
from oslo_policy import policy

from barbican.common.policies import base


deprecated_orders_get = policy.DeprecatedRule(
    name='orders:get',
    check_str='rule:all_but_audit',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_orders_post = policy.DeprecatedRule(
    name='orders:post',
    check_str='rule:admin_or_creator',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_orders_put = policy.DeprecatedRule(
    name='orders:put',
    check_str='rule:admin_or_creator',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_order_get = policy.DeprecatedRule(
    name='order:get',
    check_str='rule:all_users and project_id:%(target.order.project_id)s',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_order_delete = policy.DeprecatedRule(
    name='order:delete',
    check_str='rule:admin and project_id:%(target.order.project_id)s',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='orders:get',
        check_str="True:%(enforce_new_defaults)s and role:member",
        scope_types=['project'],
        description='Gets list of all orders associated with a project.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_orders_get
    ),
    policy.DocumentedRuleDefault(
        name='orders:post',
        check_str="True:%(enforce_new_defaults)s and role:member",
        scope_types=['project'],
        description='Creates an order.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_orders_post

    ),
    policy.DocumentedRuleDefault(
        name='orders:put',
        check_str="True:%(enforce_new_defaults)s and role:member",
        scope_types=['project'],
        description='Unsupported method for the orders API.',
        operations=[
            {
                'path': '/v1/orders',
                'method': 'PUT'
            }
        ],
        deprecated_rule=deprecated_orders_put
    ),
    policy.DocumentedRuleDefault(
        name='order:get',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "rule:order_project_member"),
        scope_types=['project'],
        description='Retrieves an orders metadata.',
        operations=[
            {
                'path': '/v1/orders/{order-id}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_order_get
    ),
    policy.DocumentedRuleDefault(
        name='order:delete',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "rule:order_project_member"),
        scope_types=['project'],
        description='Deletes an order.',
        operations=[
            {
                'path': '/v1/orders/{order-id}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_order_delete
    )
]


def list_rules():
    return rules
