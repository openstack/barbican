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
    policy.RuleDefault('consumer:get',
                       'rule:admin or rule:observer or rule:creator or '
                       'rule:audit or rule:container_non_private_read or '
                       'rule:container_project_creator or '
                       'rule:container_project_admin or '
                       'rule:container_acl_read'),
    policy.RuleDefault('consumers:get',
                       'rule:admin or rule:observer or rule:creator or '
                       'rule:audit or rule:container_non_private_read or '
                       'rule:container_project_creator or '
                       'rule:container_project_admin or '
                       'rule:container_acl_read'),
    policy.RuleDefault('consumers:post',
                       'rule:admin or rule:container_non_private_read or '
                       'rule:container_project_creator or '
                       'rule:container_project_admin or '
                       'rule:container_acl_read'),
    policy.RuleDefault('consumers:delete',
                       'rule:admin or rule:container_non_private_read or '
                       'rule:container_project_creator or '
                       'rule:container_project_admin or '
                       'rule:container_acl_read'),
]


def list_rules():
    return rules
