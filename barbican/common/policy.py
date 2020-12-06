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

from oslo_policy import opts
from oslo_policy import policy

from barbican.common import config
from barbican.common import policies

CONF = config.CONF
ENFORCER = None


# TODO(gmann): Remove setting the default value of config policy_file
# once oslo_policy change the default value to 'policy.yaml'.
# https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
DEFAULT_POLICY_FILE = 'policy.yaml'
opts.set_defaults(CONF, DEFAULT_POLICY_FILE)


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
