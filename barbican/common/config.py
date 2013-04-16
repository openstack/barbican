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
Configuration setup for Barbican.
"""


import os
from oslo.config import cfg

# Ensure the local python config path is on the list to pull config info from
CONF_FILES = cfg.find_config_files(prog='barbican-api')

#CONF_FILES = cfg.find_config_files(project='barbican', prog='barbican-api')
CONF_FILES.append('./etc/barbican/barbican-api.conf')
CONF_FILES.append('../etc/barbican/barbican-api.conf')
CONF_FILES = [cfile for cfile in CONF_FILES if os.path.isfile(cfile)]

# Set configuration files
CONF = cfg.CONF
CONF(prog='barbican-api', default_config_files=CONF_FILES)
