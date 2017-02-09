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
    policy.RuleDefault('certificate_authorities:get_limited',
                       'rule:all_users'),
    policy.RuleDefault('certificate_authorities:get_all',
                       'rule:admin'),
    policy.RuleDefault('certificate_authorities:post',
                       'rule:admin'),
    policy.RuleDefault('certificate_authorities:get_preferred_ca',
                       'rule:all_users'),
    policy.RuleDefault('certificate_authorities:get_global_preferred_ca',
                       'rule:service_admin'),
    policy.RuleDefault('certificate_authorities:unset_global_preferred',
                       'rule:service_admin'),
    policy.RuleDefault('certificate_authority:delete',
                       'rule:admin'),
    policy.RuleDefault('certificate_authority:get',
                       'rule:all_users'),
    policy.RuleDefault('certificate_authority:get_cacert',
                       'rule:all_users'),
    policy.RuleDefault('certificate_authority:get_ca_cert_chain',
                       'rule:all_users'),
    policy.RuleDefault('certificate_authority:get_projects',
                       'rule:service_admin'),
    policy.RuleDefault('certificate_authority:add_to_project',
                       'rule:admin'),
    policy.RuleDefault('certificate_authority:remove_from_project',
                       'rule:admin'),
    policy.RuleDefault('certificate_authority:set_preferred',
                       'rule:admin'),
    policy.RuleDefault('certificate_authority:set_global_preferred',
                       'rule:service_admin'),
]


def list_rules():
    return rules
