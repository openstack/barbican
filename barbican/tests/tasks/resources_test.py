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

from mock import MagicMock
import json
import unittest

from datetime import datetime
from barbican.tasks.resources import BeginCSR
from barbican.model.models import CSR
from barbican.model.repositories import CSRRepo
from barbican.model.models import States
from barbican.common import config
from barbican.common import exception


def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenTestingVersionResource())

    return suite


class WhenBeginningCSR(unittest.TestCase):

    def setUp(self):
        self.requestor = 'requestor1234'
        self.csr = CSR()
        self.csr.id = "id1"
        self.csr.requestor = self.requestor
        self.csr.status = States.PENDING

        self.csr_repo = MagicMock()
        self.csr_repo.get.return_value = self.csr

        self.resource = BeginCSR(self.csr_repo)

    def test_should_process_csr(self):
        self.resource.process(self.csr.id)

        self.csr_repo.get.assert_called_once_with(entity_id=self.csr.id)
        assert self.csr.status == States.ACTIVE


if __name__ == '__main__':
    unittest.main()
