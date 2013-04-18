# Copyright (c) 2013 Rackspace, Inc.
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
Task resources for the Barbican API.
"""
from barbican.model.repositories import CSRRepo
from barbican.common import utils

LOG = utils.getLogger(__name__)


class BeginCSR(object):
    """Handles beginning the processing of a CSR"""

    def __init__(self, csr_repo=None):
        self.repo = csr_repo or CSRRepo()

    def process(self, csr_id):
        """Process the beginning of CSR processing."""
        LOG.debug("Processing CSR with ID = {0}".format(csr_id))
        return None
