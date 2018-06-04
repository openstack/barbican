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

import itertools

from barbican.common.policies import acls
from barbican.common.policies import base
from barbican.common.policies import consumers
from barbican.common.policies import containers
from barbican.common.policies import orders
from barbican.common.policies import quotas
from barbican.common.policies import secretmeta
from barbican.common.policies import secrets
from barbican.common.policies import secretstores
from barbican.common.policies import transportkeys


def list_rules():
    return itertools.chain(
        base.list_rules(),
        acls.list_rules(),
        consumers.list_rules(),
        containers.list_rules(),
        orders.list_rules(),
        quotas.list_rules(),
        secretmeta.list_rules(),
        secrets.list_rules(),
        secretstores.list_rules(),
        transportkeys.list_rules(),
    )
