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


deprecated_secret_decrypt = policy.DeprecatedRule(
    name='secret:decrypt',
    check_str='rule:secret_decrypt_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_get = policy.DeprecatedRule(
    name='secret:get',
    check_str='rule:secret_non_private_read or ' +
              'rule:secret_project_creator or ' +
              'rule:secret_project_admin or rule:secret_acl_read',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_put = policy.DeprecatedRule(
    name='secret:put',
    check_str='rule:admin_or_creator and rule:secret_project_match',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secret_delete = policy.DeprecatedRule(
    name='secret:delete',
    check_str='rule:secret_project_admin or ' +
              'rule:secret_project_creator or ' +
              '(rule:secret_project_creator_role and ' +
              'not rule:secret_private_read)',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secrets_post = policy.DeprecatedRule(
    name='secrets:post',
    check_str='rule:admin_or_creator',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_secrets_get = policy.DeprecatedRule(
    name='secrets:get',
    check_str='rule:all_but_audit',
    deprecated_reason=base.LEGACY_POLICY_DEPRECATION,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    policy.DocumentedRuleDefault(
        name='secret:decrypt',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private) or "
            "rule:secret_acl_read)"),
        scope_types=['project'],
        description='Retrieve a secrets payload.',
        operations=[
            {
                'path': '/v1/secrets/{uuid}/payload',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secret_decrypt
    ),
    policy.DocumentedRuleDefault(
        name='secret:get',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private) or "
            "rule:secret_acl_read)"),
        scope_types=['project'],
        description='Retrieves a secrets metadata.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secret_get
    ),
    policy.DocumentedRuleDefault(
        name='secret:put',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Add the payload to an existing metadata-only secret.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'PUT'
            }
        ],
        deprecated_rule=deprecated_secret_put
    ),
    policy.DocumentedRuleDefault(
        name='secret:delete',
        check_str=(
            "True:%(enforce_new_defaults)s and "
            "(rule:secret_project_admin or "
            "(rule:secret_project_member and rule:secret_owner) or "
            "(rule:secret_project_member and rule:secret_is_not_private))"),
        scope_types=['project'],
        description='Delete a secret by uuid.',
        operations=[
            {
                'path': '/v1/secrets/{secret-id}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_secret_delete
    ),
    policy.DocumentedRuleDefault(
        name='secrets:post',
        check_str=f'True:%(enforce_new_defaults)s and role:member',
        scope_types=['project'],
        description='Creates a Secret entity.',
        operations=[
            {
                'path': '/v1/secrets',
                'method': 'POST'
            }
        ],
        deprecated_rule=deprecated_secrets_post
    ),
    policy.DocumentedRuleDefault(
        name='secrets:get',
        check_str=f'True:%(enforce_new_defaults)s and role:member',
        scope_types=['project'],
        description='Lists a projects secrets.',
        operations=[
            {
                'path': '/v1/secrets',
                'method': 'GET'
            }
        ],
        deprecated_rule=deprecated_secrets_get
    )
]


def list_rules():
    return rules
