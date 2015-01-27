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
Configuration setup for Barbican.
"""

import logging
import os

from oslo_config import cfg

import barbican.version

CONF = cfg.CONF
CONF.import_opt('verbose', 'barbican.openstack.common.log')
CONF.import_opt('debug', 'barbican.openstack.common.log')
CONF.import_opt('log_dir', 'barbican.openstack.common.log')
CONF.import_opt('log_file', 'barbican.openstack.common.log')
CONF.import_opt('log_config_append', 'barbican.openstack.common.log')
CONF.import_opt('log_format', 'barbican.openstack.common.log')
CONF.import_opt('log_date_format', 'barbican.openstack.common.log')
CONF.import_opt('use_syslog', 'barbican.openstack.common.log')
CONF.import_opt('syslog_log_facility', 'barbican.openstack.common.log')

LOG = logging.getLogger(__name__)


def parse_args(args=None, usage=None, default_config_files=None):
    CONF(args=args,
         project='barbican',
         prog='barbican-api',
         version=barbican.version.__version__,
         usage=usage,
         default_config_files=default_config_files)

    CONF.pydev_debug_host = os.environ.get('PYDEV_DEBUG_HOST')
    CONF.pydev_debug_port = os.environ.get('PYDEV_DEBUG_PORT')


def setup_remote_pydev_debug():
    """Required setup for remote debugging."""

    if CONF.pydev_debug_host and CONF.pydev_debug_port:
        try:
            try:
                from pydev import pydevd
            except ImportError:
                import pydevd

            pydevd.settrace(CONF.pydev_debug_host,
                            port=int(CONF.pydev_debug_port),
                            stdoutToServer=True,
                            stderrToServer=True)
        except Exception:
            LOG.exception('Unable to join debugger, please '
                          'make sure that the debugger processes is '
                          'listening on debug-host \'%s\' debug-port \'%s\'.',
                          CONF.pydev_debug_host, CONF.pydev_debug_port)
            raise
