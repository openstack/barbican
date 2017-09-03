# Copyright  2011-2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy

from oslo_policy import policy

from barbican.common import config
from barbican.common import policies

CONF = config.CONF
ENFORCER = None
# oslo_policy will read the policy configuration file again when the file
# is changed in runtime so the old policy rules will be saved to
# saved_file_rules and used to compare with new rules to determine the
# rules whether were updated.
saved_file_rules = []


def reset():
    global ENFORCER
    if ENFORCER:
        ENFORCER.clear()
    ENFORCER = None


def init():
    global ENFORCER
    global saved_file_rules

    if not ENFORCER:
        ENFORCER = policy.Enforcer(CONF)
        register_rules(ENFORCER)
        ENFORCER.load_rules()

    # Only the rules which are loaded from file may be changed.
    current_file_rules = ENFORCER.file_rules
    current_file_rules = _serialize_rules(current_file_rules)

    # Checks whether the rules are updated in the runtime
    if saved_file_rules != current_file_rules:
        saved_file_rules = copy.deepcopy(current_file_rules)


def _serialize_rules(rules):
    """Serialize all the Rule object as string."""

    result = [(rule_name, str(rule))
              for rule_name, rule in rules.items()]
    return sorted(result, key=lambda rule: rule[0])


def register_rules(enforcer):
    enforcer.register_defaults(policies.list_rules())


def get_enforcer():
    init()
    return ENFORCER
