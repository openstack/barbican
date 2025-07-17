#!/usr/bin/env python3

# Copyright (c) 2015 Rackspace, Inc.
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
Server startup application for barbican-retry-scheduler
"""
import sys

from barbican.common import config
from barbican import queue
from barbican.queue import retry_scheduler
from barbican import version

from oslo_log import log
from oslo_service import service


def fail(returncode, e):
    sys.stderr.write("ERROR: {0}\n".format(e))
    sys.exit(returncode)


def main():
    try:
        CONF = config.CONF
        CONF(sys.argv[1:], project='barbican',
             version=version.version_info.version_string)

        # Import and configure logging.
        log.setup(CONF, 'barbican-retry-scheduler')
        LOG = log.getLogger(__name__)
        LOG.debug("Booting up Barbican worker retry/scheduler node...")

        # Queuing initialization (as a client only).
        queue.init(CONF, is_server_side=False)

        service.launch(
            CONF,
            retry_scheduler.PeriodicServer(),
            restart_method='mutate'
        ).wait()
    except RuntimeError as e:
        fail(1, e)


if __name__ == '__main__':
    main()
