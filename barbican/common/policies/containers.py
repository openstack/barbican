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


deprecated_containers_post = policy.DeprecatedRule(
    name='containers:post',
    check_str='rule:admin_or_creator',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_containers_get = policy.DeprecatedRule(
    name='containers:get',
    check_str='rule:all_but_audit',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_get = policy.DeprecatedRule(
    name='container:get',
    check_str='rule:container_non_private_read or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_admin or ' +
              'rule:container_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_delete = policy.DeprecatedRule(
    name='container:delete',
    check_str='rule:container_project_admin or ' +
              'rule:container_project_creator',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_secret_post = policy.DeprecatedRule(
    name='container_secret:post',
    check_str='rule:container_project_admin or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_creator_role and ' +
              'rule:container_non_private_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_secret_delete = policy.DeprecatedRule(
    name='container_secret:delete',
    check_str='rule:container_project_admin or ' +
              'rule:container_project_creator or ' +
              'rule:container_project_creator_role and ' +
              'rule:container_non_private_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='containers:post',
        check_str='True:%(enforce_new_defaults)s and role:member',
        scope_types=['project'],
        description='Creates a container.',
        operations=[
            {
                'path': '/v1/containers',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_containers_post
    ),
    policy.DocumentedRuleDefault(
        name='containers:get',
        check_str='True:%(enforce_new_defaults)s and role:member',
        scope_types=['project'],
        description='Lists a projects containers.',
        operations=[
            {
                'path': '/v1/containers',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_containers_get
    ),
    policy.DocumentedRuleDefault(
        name='container:get',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private) or '
            'rule:container_acl_read)'),
        scope_types=['project'],
        description='Retrieves a single container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_container_get
    ),
    policy.DocumentedRuleDefault(
        name='container:delete',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private))'),
        scope_types=['project'],
        description='Deletes a container.',
        operations=[
            {
                'path': '/v1/containers/{uuid}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_container_delete
    ),
    policy.DocumentedRuleDefault(
        name='container_secret:post',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private))'),
        scope_types=['project'],
        description='Add a secret to an existing container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/secrets',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_container_secret_post
    ),
    policy.DocumentedRuleDefault(
        name='container_secret:delete',
        check_str=(
            'True:%(enforce_new_defaults)s and '
            '(rule:container_project_admin or '
            '(rule:container_project_member and rule:container_owner) or '
            '(rule:container_project_member and '
            ' rule:container_is_not_private))'),
        scope_types=['project'],
        description='Remove a secret from a container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/secrets/{secret-id}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_container_secret_delete
    ),
]


def list_rules():
    return rules
