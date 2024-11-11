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


# TODO(gmann): Remove setting the default value of config:
# - 'enforce_scope', and 'enforce_new_defaults' once barbican is ready with the
# new RBAC (oslo_policy enable them by default)
opts.set_defaults(
    CONF,
    enforce_scope=False,
    enforce_new_defaults=False)


def reset():
    global ENFORCER
    if ENFORCER:
        ENFORCER.clear()
    ENFORCER = None


def init(suppress_deprecation_warnings=False):
    """Init an Enforcer class.

    :param suppress_deprecation_warnings: Whether to suppress the deprecation
        warnings.
    """
    global ENFORCER
    global saved_file_rules

    if not ENFORCER:
        ENFORCER = policy.Enforcer(CONF)

        # NOTE(gmann): Explictly disable the warnings for policies
        # changing their default check_str. During policy-defaults-refresh
        # work, all the policy defaults have been changed and warning for
        # each policy started filling the logs limit for various tool.
        # Once we move to new defaults only world then we can enable these
        # warning again.
        ENFORCER.suppress_default_change_warnings = True
        if suppress_deprecation_warnings:
            ENFORCER.suppress_deprecation_warnings = True

        register_rules(ENFORCER)
        ENFORCER.load_rules()


def register_rules(enforcer):
    enforcer.register_defaults(policies.list_rules())


def get_enforcer():
    init()
    return ENFORCER
