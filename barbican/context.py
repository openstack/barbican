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

import oslo_context

from barbican.common import policy


class RequestContext(oslo_context.context.RequestContext):
    """User security context object

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    def __init__(self, policy_enforcer=None, **kwargs):
        # prefer usage of 'project' instead of 'tenant'
        if policy_enforcer:
            self.policy_enforcer = policy_enforcer
        else:
            policy.init()
            self.policy_enforcer = policy.get_enforcer()
        super(RequestContext, self).__init__(**kwargs)

    def to_dict(self):
        out_dict = super(RequestContext, self).to_dict()
        out_dict['roles'] = self.roles

        return out_dict

    @classmethod
    def from_dict(cls, values):
        return cls(**values)
