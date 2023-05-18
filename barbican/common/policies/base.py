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


LEGACY_POLICY_DEPRECATION = (
    'The default policy for the Key Manager API has been updated '
    'to use scopes and default roles.'
)

rules = [
    policy.RuleDefault(
        name='secret_project_match',
        check_str='project_id:%(target.secret.project_id)s'),
    policy.RuleDefault(
        name='secret_project_reader',
        check_str='role:reader and rule:secret_project_match'),
    policy.RuleDefault(
        name='secret_project_member',
        check_str='role:member and rule:secret_project_match'),
    policy.RuleDefault(
        name='secret_project_admin',
        check_str='role:admin and rule:secret_project_match'),
    policy.RuleDefault(
        name='secret_owner',
        check_str='user_id:%(target.secret.creator_id)s'),
    policy.RuleDefault(
        name='secret_is_not_private',
        check_str='True:%(target.secret.read_project_access)s'),
    policy.RuleDefault(
        name='secret_acl_read',
        check_str="'read':%(target.secret.read)s"),

    policy.RuleDefault(
        name='container_project_match',
        check_str="project_id:%(target.container.project_id)s"),
    policy.RuleDefault(
        name='container_project_member',
        check_str='role:member and rule:container_project_match'),
    policy.RuleDefault(
        name='container_project_admin',
        check_str='role:admin and rule:container_project_match'),
    policy.RuleDefault(
        name='container_owner',
        check_str="user_id:%(target.container.creator_id)s"),
    policy.RuleDefault(
        name='container_is_not_private',
        check_str='True:%(target.container.read_project_access)s'),
    policy.RuleDefault(
        name='container_acl_read',
        check_str="'read':%(target.container.read)s"),

    policy.RuleDefault(
        name='order_project_match',
        check_str='project_id:%(target.order.project_id)s'),
    policy.RuleDefault(
        name='order_project_member',
        check_str='role:member and rule:order_project_match'),

    # NOTE(dmendiza):
    # The default rules below are only used in the deprecated legacy policy
    # and should be removed when the legacy policy is eventually dropped.
    policy.RuleDefault(
        name='audit',
        check_str='role:audit'),
    policy.RuleDefault(
        name='observer',
        check_str='role:observer'),
    policy.RuleDefault(
        name='creator',
        check_str='role:creator'),
    policy.RuleDefault(
        name='admin',
        check_str='role:admin'),
    policy.RuleDefault(
        name='service_admin',
        check_str='role:key-manager:service-admin'),
    policy.RuleDefault(
        name='all_users',
        check_str='rule:admin or rule:observer or rule:creator or ' +
                  'rule:audit or rule:service_admin'),
    policy.RuleDefault(
        name='all_but_audit',
        check_str='rule:admin or rule:observer or rule:creator'),
    policy.RuleDefault(
        name='admin_or_creator',
        check_str='rule:admin or rule:creator'),

    policy.RuleDefault(
        name='secret_creator_user',
        check_str="user_id:%(target.secret.creator_id)s"),
    policy.RuleDefault(
        name='secret_private_read',
        check_str="'False':%(target.secret.read_project_access)s"),
    policy.RuleDefault(
        name='secret_non_private_read',
        check_str="rule:all_users and rule:secret_project_match and not " +
                  "rule:secret_private_read"),
    policy.RuleDefault(
        name='secret_decrypt_non_private_read',
        check_str="rule:all_but_audit and rule:secret_project_match and not " +
                  "rule:secret_private_read"),
    policy.RuleDefault(
        name='secret_project_creator',
        check_str="rule:creator and rule:secret_project_match and " +
                  "rule:secret_creator_user"),
    policy.RuleDefault(
        name='secret_project_creator_role',
        check_str="rule:creator and rule:secret_project_match"),

    policy.RuleDefault(
        name='container_private_read',
        check_str="'False':%(target.container.read_project_access)s"),
    policy.RuleDefault(
        name='container_creator_user',
        check_str="user_id:%(target.container.creator_id)s"),
    policy.RuleDefault(
        name='container_non_private_read',
        check_str="rule:all_users and rule:container_project_match and not " +
                  "rule:container_private_read"),
    policy.RuleDefault(
        name='container_project_creator',
        check_str="rule:creator and rule:container_project_match and " +
                  "rule:container_creator_user"),
    policy.RuleDefault(
        name='container_project_creator_role',
        check_str="rule:creator and rule:container_project_match"),
]


def list_rules():
    return rules
