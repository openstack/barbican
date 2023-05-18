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


deprecated_transport_key_get = policy.DeprecatedRule(
    name='transport_key:get',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_transport_key_delete = policy.DeprecatedRule(
    name='transport_key:delete',
    check_str='rule:service_admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_transport_keys_get = policy.DeprecatedRule(
    name='transport_keys:get',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_transport_keys_post = policy.DeprecatedRule(
    name='transport_keys:post',
    check_str='rule:service_admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='transport_key:get',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get a specific transport key.',
        operations=[
            {
                'path': '/v1/transport_keys/{key-id}}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_transport_key_get
    ),
    policy.DocumentedRuleDefault(
        name='transport_key:delete',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Delete a specific transport key.',
        operations=[
            {
                'path': '/v1/transport_keys/{key-id}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_transport_key_delete
    ),
    policy.DocumentedRuleDefault(
        name='transport_keys:get',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get a list of all transport keys.',
        operations=[
            {
                'path': '/v1/transport_keys',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_transport_keys_get
    ),
    policy.DocumentedRuleDefault(
        name='transport_keys:post',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Create a new transport key.',
        operations=[
            {
                'path': '/v1/transport_keys',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_transport_keys_post
    ),

]


def list_rules():
    return rules
