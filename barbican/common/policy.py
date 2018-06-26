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

from oslo_policy import policy

from barbican.common import config
from barbican.common import policies

CONF = config.CONF
ENFORCER = None


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


def register_rules(enforcer):
    enforcer.register_defaults(policies.list_rules())


def get_enforcer():
    init()
    return ENFORCER
