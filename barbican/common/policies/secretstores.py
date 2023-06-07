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


deprecated_secretstores_get = policy.DeprecatedRule(
    name='secretstores:get',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secretstores_get_global = policy.DeprecatedRule(
    name='secretstores:get_global_default',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secretstores_get_preferred = policy.DeprecatedRule(
    name='secretstores:get_preferred',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secretstores_preferred_post = policy.DeprecatedRule(
    name='secretstore_preferred:post',
    check_str='rule:admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secretstores_preferred_delete = policy.DeprecatedRule(
    name='secretstore_preferred:delete',
    check_str='rule:admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secretstore_get = policy.DeprecatedRule(
    name='secretstore:get',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='secretstores:get',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get list of available secret store backends.',
        operations=[
            {
                'path': '/v1/secret-stores',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secretstores_get
    ),
    policy.DocumentedRuleDefault(
        name='secretstores:get_global_default',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get a reference to the secret store that is used as ' +
                    'default secret store backend for the deployment.',
        operations=[
            {
                'path': '/v1/secret-stores/global-default',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secretstores_get_global
    ),
    policy.DocumentedRuleDefault(
        name='secretstores:get_preferred',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get a reference to the preferred secret store if ' +
                    'assigned previously.',
        operations=[
            {
                'path': '/v1/secret-stores/preferred',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secretstores_get_preferred
    ),
    policy.DocumentedRuleDefault(
        name='secretstore_preferred:post',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Set a secret store backend to be preferred store ' +
                    'backend for their project.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}/preferred',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_secretstores_preferred_post
    ),
    policy.DocumentedRuleDefault(
        name='secretstore_preferred:delete',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Remove preferred secret store backend setting for ' +
                    'their project.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}/preferred',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_secretstores_preferred_delete
    ),
    policy.DocumentedRuleDefault(
        name='secretstore:get',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='Get details of secret store by its ID.',
        operations=[
            {
                'path': '/v1/secret-stores/{ss-id}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secretstore_get
    ),
]


def list_rules():
    return rules
