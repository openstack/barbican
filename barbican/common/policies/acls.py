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
    policy.RuleDefault('secret_acls:put_patch',
                       'rule:secret_project_admin or '
                       'rule:secret_project_creator'),
    policy.RuleDefault('secret_acls:delete',
                       'rule:secret_project_admin or '
                       'rule:secret_project_creator'),
    policy.RuleDefault('secret_acls:get',
                       'rule:all_but_audit and '
                       'rule:secret_project_match'),
    policy.RuleDefault('container_acls:put_patch',
                       'rule:container_project_admin or '
                       'rule:container_project_creator'),
    policy.RuleDefault('container_acls:delete',
                       'rule:container_project_admin or '
                       'rule:container_project_creator'),
    policy.RuleDefault('container_acls:get',
                       'rule:all_but_audit and rule:container_project_match'),
]


def list_rules():
    return rules
