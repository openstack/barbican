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


deprecated_secret_meta_get = policy.DeprecatedRule(
    name='secret_meta:get',
    check_str='rule:secret_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_meta_post = policy.DeprecatedRule(
    name='secret_meta:post',
    check_str='rule:secret_project_admin or ' +
              'rule:secret_project_creator or ' +
              '(rule:secret_project_creator_role and ' +
              'rule:secret_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_meta_put = policy.DeprecatedRule(
    name='secret_meta:put',
    check_str='rule:secret_project_admin or ' +
              'rule:secret_project_creator or ' +
              '(rule:secret_project_creator_role and ' +
              'rule:secret_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_meta_delete = policy.DeprecatedRule(
    name='secret_meta:delete',
    check_str='rule:secret_project_admin or ' +
              'rule:secret_project_creator or ' +
              '(rule:secret_project_creator_role and ' +
              'rule:secret_non_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='secret_meta:get',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private) or "
            "rule:secret_acl_read)"),
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
        ],
        deprecated_rule=deprecated_secret_meta_get
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:post',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Adds a new key/value pair to the secrets user-defined ' +
                    'metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_secret_meta_post
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:put',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
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
        ],
        deprecated_rule=deprecated_secret_meta_put
    ),
    policy.DocumentedRuleDefault(
        name='secret_meta:delete',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Delete secret user-defined metadata by key.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}/metadata/{meta-key}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_secret_meta_delete
    ),
]


def list_rules():
    return rules
