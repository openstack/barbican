"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os

from tempest import config

CONF = config.CONF

# Use local tempest conf if one is available.
# This usually means we're running tests outside of devstack
if os.path.exists('./etc/dev_tempest.conf'):
    CONF.set_config_path('./etc/dev_tempest.conf')