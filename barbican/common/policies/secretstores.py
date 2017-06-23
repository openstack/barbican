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
    policy.RuleDefault('secretstores:get',
                       'rule:admin'),
    policy.RuleDefault('secretstores:get_global_default',
                       'rule:admin'),
    policy.RuleDefault('secretstores:get_preferred',
                       'rule:admin'),
    policy.RuleDefault('secretstore_preferred:post',
                       'rule:admin'),
    policy.RuleDefault('secretstore_preferred:delete',
                       'rule:admin'),
    policy.RuleDefault('secretstore:get',
                       'rule:admin'),
]


def list_rules():
    return rules
