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
    policy.RuleDefault('secret:decrypt',
                       'rule:secret_decrypt_non_private_read or '
                       'rule:secret_project_creator or '
                       'rule:secret_project_admin or '
                       'rule:secret_acl_read'),
    policy.RuleDefault('secret:get',
                       'rule:secret_non_private_read or '
                       'rule:secret_project_creator or '
                       'rule:secret_project_admin or '
                       'rule:secret_acl_read'),
    policy.RuleDefault('secret:put',
                       'rule:admin_or_creator and '
                       'rule:secret_project_match'),
    policy.RuleDefault('secret:delete',
                       'rule:secret_project_admin or '
                       'rule:secret_project_creator'),
    policy.RuleDefault('secrets:post',
                       'rule:admin_or_creator'),
    policy.RuleDefault('secrets:get',
                       'rule:all_but_audit'),
]


def list_rules():
    return rules
