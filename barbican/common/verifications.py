# Copyright (c) 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Resource verification business logic.
"""
from barbican.common import utils


LOG = utils.getLogger(__name__)


def verify(verification):
    """Verifies if a resource is 'valid' for an action or not.

    Based on the target resource information in the supplied verification
    entity this function determines if it is valid to use for the specified
    action. The supplied entity is then updated with the processing result.

    :param verification: A Verification entity
    """
    if 'image' == verification.resource_type:
        #TODO(jfwood) Add rules or else consider a plugin approach similar to
        #  barbican/crypto/plugin.py.
        verification.is_verified = True
