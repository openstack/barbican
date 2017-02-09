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


rules = [
    policy.RuleDefault('admin',
                       'role:admin'),
    policy.RuleDefault('observer',
                       'role:observer'),
    policy.RuleDefault('creator',
                       'role:creator'),
    policy.RuleDefault('audit',
                       'role:audit'),
    policy.RuleDefault('service_admin',
                       'role:key-manager:service-admin'),
    policy.RuleDefault('admin_or_user_does_not_work',
                       'project_id:%(project_id)s'),
    policy.RuleDefault('admin_or_user',
                       'rule:admin or project_id:%(project_id)s'),
    policy.RuleDefault('admin_or_creator',
                       'rule:admin or rule:creator'),
    policy.RuleDefault('all_but_audit',
                       'rule:admin or rule:observer or rule:creator'),
    policy.RuleDefault('all_users',
                       'rule:admin or rule:observer or rule:creator or '
                       'rule:audit or rule:service_admin'),
    policy.RuleDefault('secret_project_match',
                       'project:%(target.secret.project_id)s'),
    policy.RuleDefault('secret_acl_read',
                       "'read':%(target.secret.read)s"),
    policy.RuleDefault('secret_private_read',
                       "'False':%(target.secret.read_project_access)s"),
    policy.RuleDefault('secret_creator_user',
                       "user:%(target.secret.creator_id)s"),
    policy.RuleDefault('container_project_match',
                       "project:%(target.container.project_id)s"),
    policy.RuleDefault('container_acl_read',
                       "'read':%(target.container.read)s"),
    policy.RuleDefault('container_private_read',
                       "'False':%(target.container.read_project_access)s"),
    policy.RuleDefault('container_creator_user',
                       "user:%(target.container.creator_id)s"),
    policy.RuleDefault('secret_non_private_read',
                       "rule:all_users and rule:secret_project_match and "
                       "not rule:secret_private_read"),
    policy.RuleDefault('secret_decrypt_non_private_read',
                       "rule:all_but_audit and rule:secret_project_match and "
                       "not rule:secret_private_read"),
    policy.RuleDefault('container_non_private_read',
                       "rule:all_users and rule:container_project_match and "
                       "not rule:container_private_read"),
    policy.RuleDefault('secret_project_admin',
                       "rule:admin and rule:secret_project_match"),
    policy.RuleDefault('secret_project_creator',
                       "rule:creator and rule:secret_project_match and "
                       "rule:secret_creator_user"),
    policy.RuleDefault('container_project_admin',
                       "rule:admin and rule:container_project_match"),
    policy.RuleDefault('container_project_creator',
                       "rule:creator and rule:container_project_match and "
                       "rule:container_creator_user"),
]


def list_rules():
    return rules
