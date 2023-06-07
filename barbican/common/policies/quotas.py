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


deprecated_quotas_get = policy.DeprecatedRule(
    name='quotas:get',
    check_str='rule:all_users',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_project_quotas_get = policy.DeprecatedRule(
    name='project_quotas:get',
    check_str='rule:service_admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_project_quotas_put = policy.DeprecatedRule(
    name='project_quotas:put',
    check_str='rule:service_admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_project_quotas_delete = policy.DeprecatedRule(
    name='project_quotas:delete',
    check_str='rule:service_admin',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='quotas:get',
        check_str='True:%(enforce_new_defaults)s and role:reader',
        scope_types=['project'],
        description='List quotas for the project the user belongs to.',
        operations=[
            {
                'path': '/v1/quotas',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_quotas_get
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:get',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='List quotas for the specified project.',
        operations=[
            {
                'path': '/v1/project-quotas',
                'method': 'GET'
            },
            {
                'path': '/v1/project-quotas/{uuid}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_project_quotas_get
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:put',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Create or update the configured project quotas for '
                    'the project with the specified UUID.',
        operations=[
            {
                'path': '/v1/project-quotas/{uuid}',
                'method': 'PUT'
            }
        ],
        deprecated_rule=deprecated_project_quotas_put
    ),
    policy.DocumentedRuleDefault(
        name='project_quotas:delete',
        check_str='True:%(enforce_new_defaults)s and role:admin',
        scope_types=['project'],
        description='Delete the project quotas configuration for the '
                    'project with the requested UUID.',
        operations=[
            {
                'path': '/v1/quotas}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_project_quotas_delete
    ),
]


def list_rules():
    return rules
