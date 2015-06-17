#!/usr/bin/env python
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
Barbican Keystone notification listener server.
"""

import eventlet
import os
import sys

# Oslo messaging notification server uses eventlet.
#
# To have remote debugging, thread module needs to be disabled.
# eventlet.monkey_patch(thread=False)
eventlet.monkey_patch()


# 'Borrowed' from the Glance project:
# If ../barbican/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'barbican', '__init__.py')):
    sys.path.insert(0, possible_topdir)


from barbican.common import config
from barbican import queue
from barbican.queue import keystone_listener

from oslo_log import log
from oslo_service import service


def fail(returncode, e):
    sys.stderr.write("ERROR: {0}\n".format(e))
    sys.exit(returncode)


if __name__ == '__main__':
    try:
        config.setup_remote_pydev_debug()
        # Import and configure logging.
        log.setup('barbican')

        LOG = log.getLogger(__name__)
        LOG.info("Booting up Barbican Keystone listener node...")

        # Queuing initialization
        CONF = config.CONF
        queue.init(CONF)

        if getattr(getattr(CONF, queue.KS_NOTIFICATIONS_GRP_NAME), 'enable'):
            service.launch(
                CONF,
                keystone_listener.MessageServer(CONF)
            ).wait()
        else:
            LOG.info("Exiting as Barbican Keystone listener is not enabled...")
    except RuntimeError as e:
        fail(1, e)
