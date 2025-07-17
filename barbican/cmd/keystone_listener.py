#!/usr/bin/env python3
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
Server startup application for barbican-keystone-listener
"""
import sys

from barbican.common import config
from barbican import queue
from barbican.queue import keystone_listener
from barbican import version

from oslo_log import log
from oslo_service.backend import BackendType
from oslo_service.backend import init_backend
from oslo_service import service


def fail(returncode, e):
    sys.stderr.write("ERROR: {0}\n".format(e))
    sys.exit(returncode)


def main():
    try:
        config.setup_remote_pydev_debug()

        # Ensure oslo.service uses the threading backend early
        init_backend(BackendType.THREADING)

        CONF = config.CONF
        CONF(sys.argv[1:], project='barbican',
             version=version.version_info.version_string)

        # Import and configure logging.
        log.setup(CONF, 'barbican')

        LOG = log.getLogger(__name__)
        LOG.info("Booting up Barbican Keystone listener node...")

        # Queuing initialization
        queue.init(CONF)

        if getattr(getattr(CONF, queue.KS_NOTIFICATIONS_GRP_NAME), 'enable'):
            service.launch(
                CONF,
                keystone_listener.MessageServer(CONF),
                restart_method='mutate'
            ).wait()
        else:
            LOG.info("Exiting as Barbican Keystone listener is not enabled...")
    except RuntimeError as e:
        fail(1, e)


if __name__ == '__main__':
    sys.exit(main())
