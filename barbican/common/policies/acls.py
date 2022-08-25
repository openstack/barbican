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


# FIXME(hrybacki): Repetitive check strings: Port to simpler checks
#                  - secret_acls:delete, secret_acls:put_patch
#                  - container_acls:delete container_acls:put_patch

deprecated_secret_acls_get = policy.DeprecatedRule(
    name='secret_acls:get',
    check_str='rule:all_but_audit and rule:secret_project_match',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_acls_delete = policy.DeprecatedRule(
    name='secret_acls:delete',
    check_str='rule:secret_project_admin or rule:secret_project_creator ' +
              'or (rule:secret_project_creator_role and ' +
              'rule:secret_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_acls_put_patch = policy.DeprecatedRule(
    name='secret_acls:put_patch',
    check_str='rule:secret_project_admin or rule:secret_project_creator ' +
              'or (rule:secret_project_creator_role and ' +
              'rule:secret_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_acls_get = policy.DeprecatedRule(
    name='container_acls:get',
    check_str='rule:all_but_audit and rule:container_project_match',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_acls_delete = policy.DeprecatedRule(
    name='container_acls:delete',
    check_str='rule:container_project_admin or ' +
              'rule:container_project_creator or ' +
              '(rule:container_project_creator_role and' +
              ' rule:container_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_container_acls_put_patch = policy.DeprecatedRule(
    name='container_acls:put_patch',
    check_str='rule:container_project_admin or ' +
              'rule:container_project_creator or ' +
              '(rule:container_project_creator_role and' +
              ' rule:container_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='secret_acls:get',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Retrieve the ACL settings for a given secret.'
                    'If no ACL is defined for that secret, then Default ACL '
                    'is returned.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'GET'
            },
        ],
        deprecated_rule=deprecated_secret_acls_get
    ),
    policy.DocumentedRuleDefault(
        name='secret_acls:delete',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Delete the ACL settings for a given secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'DELETE'
            },
        ],
        deprecated_rule=deprecated_secret_acls_delete
    ),
    policy.DocumentedRuleDefault(
        name='secret_acls:put_patch',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Create new, replaces, or updates existing ACL for a ' +
                    'given secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'PUT'
            },
            {
                'path': '/v1/secrets/{secret-id}/acl',
                'method': 'PATCH'
            },
        ],
        deprecated_rule=deprecated_secret_acls_put_patch
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:get',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:container_project_admin or "
            "(rule:container_project_member and rule:container_owner) or "
            "(rule:container_project_member and "
            " rule:container_is_not_private))"),
        scope_types=['project'],
        description='Retrieve the ACL settings for a given container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_container_acls_get
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:delete',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:container_project_admin or "
            "(rule:container_project_member and rule:container_owner) or "
            "(rule:container_project_member and "
            " rule:container_is_not_private))"),
        scope_types=['project'],
        description='Delete ACL for a given container. No content is returned '
                    'in the case of successful deletion.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_container_acls_delete
    ),
    policy.DocumentedRuleDefault(
        name='container_acls:put_patch',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:container_project_admin or "
            "(rule:container_project_member and rule:container_owner) or "
            "(rule:container_project_member and "
            " rule:container_is_not_private))"),
        scope_types=['project'],
        description='Create new or replaces existing ACL for a given '
                    'container.',
        operations=[
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'PUT'
            },
            {
                'path': '/v1/containers/{container-id}/acl',
                'method': 'PATCH'
            }
        ],
        deprecated_rule=deprecated_container_acls_put_patch
    ),
]


def list_rules():
    return rules
