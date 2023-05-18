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

# FIXME(hrybacki): Note that the GET rules have the same check strings.
#                  The POST/DELETE rules also share the check stirngs.
#                  These can probably be turned into constants in base

deprecated_consumer_get = policy.DeprecatedRule(
    name='consumer:get',
    check_str='rule:admin or rule:observer or rule:creator or ' +
              'rule:audit or rule:container_non_private_read or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_admin or rule:container_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_consumers_get = policy.DeprecatedRule(
    name='container_consumers:get',
    check_str='rule:container_non_private_read or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_admin or rule:container_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_consumers_post = policy.DeprecatedRule(
    name='container_consumers:post',
    check_str='rule:container_non_private_read or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_admin or rule:container_acl_read ',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_consumers_delete = policy.DeprecatedRule(
    name='container_consumers:delete',
    check_str='rule:container_non_private_read or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_admin or rule:container_acl_read ',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_consumers_get = policy.DeprecatedRule(
    name='secret_consumers:get',
    check_str='rule:secret_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_consumers_post = policy.DeprecatedRule(
    name='secret_consumers:post',
    check_str='rule:secret_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_consumers_delete = policy.DeprecatedRule(
    name='secret_consumers:delete',
    check_str='rule:secret_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='consumer:get',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(role:admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private) or '
            'rule:container_acl_read)'),
        scope_types=['project'],
        # This API is unusable.  There is no way for a user to get
        # the consumer-id they would need to send a request.
        description='DEPRECATED: show information for a specific consumer',
        operations=[{
            'path': '/v1/containers/{container-id}/consumers/{consumer-id}',
            'method': 'GET'
        }],
        deprecated_rule=deprecated_consumer_get
    ),
    policy.DocumentedRuleDefault(
        name='container_consumers:get',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private) or '
            'rule:container_acl_read)'),
        scope_types=['project'],
        description='List a containers consumers.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_container_consumers_get
    ),
    policy.DocumentedRuleDefault(
        name='container_consumers:post',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private) or '
            'rule:container_acl_read)'),
        scope_types=['project'],
        description='Creates a consumer.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_container_consumers_post
    ),
    policy.DocumentedRuleDefault(
        name='container_consumers:delete',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private) or '
            'rule:container_acl_read)'),
        scope_types=['project'],
        description='Deletes a consumer.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/consumers',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_container_consumers_delete
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:get',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:secret_project_admin or '
            '(rule:secret_project_member and rule:secret_owner) or '
            '(rule:secret_project_member and rule:secret_is_not_private) or '
            'rule:secret_acl_read)'),
        scope_types=['project'],
        description='List consumers for a secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/consumers',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secret_consumers_get
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:post',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:secret_project_admin or '
            '(rule:secret_project_member and rule:secret_owner) or '
            '(rule:secret_project_member and rule:secret_is_not_private) or '
            'rule:secret_acl_read)'),
        scope_types=['project'],
        description='Creates a consumer.',
        operations=[
            {
                'path': '/v1/secrets/{secrets-id}/consumers',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_secret_consumers_post
    ),
    policy.DocumentedRuleDefault(
        name='secret_consumers:delete',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:secret_project_admin or '
            '(rule:secret_project_member and rule:secret_owner) or '
            '(rule:secret_project_member and rule:secret_is_not_private) or '
            'rule:secret_acl_read)'),
        scope_types=['project'],
        description='Deletes a consumer.',
        operations=[
            {
                'path': '/v1/secrets/{secrets-id}/consumers',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_secret_consumers_delete
    ),
]


def list_rules():
    return rules
