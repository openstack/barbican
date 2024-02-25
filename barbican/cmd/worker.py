#!/usr/bin/env python3

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
Barbican worker server.
"""

import eventlet
import os
import sys

# Oslo messaging RPC server uses eventlet.
eventlet.monkey_patch()
# Monkey patch the original current_thread to use the up-to-date _active
# global variable. See https://bugs.launchpad.net/bugs/1863021 and
# https://github.com/eventlet/eventlet/issues/592
import __original_module_threading as orig_threading
import threading  # noqa
orig_threading.current_thread.__globals__['_active'] = threading._active

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
from barbican.queue import server
from barbican import version

from oslo_log import log
from oslo_service import service


def main():
    try:
        CONF = config.CONF
        CONF(sys.argv[1:], project='barbican',
             version=version.version_info.version_string)

        # Import and configure logging.
        log.setup(CONF, 'barbican')
        LOG = log.getLogger(__name__)
        LOG.debug("Booting up Barbican worker node...")

        # Queuing initialization
        queue.init(CONF)

        service.launch(
            CONF,
            server.TaskServer(),
            workers=CONF.queue.asynchronous_workers,
            restart_method='mutate'
        ).wait()
    except RuntimeError as e:
        sys.stderr.write("ERROR: {0}\n".format(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
