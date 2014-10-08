#!/usr/bin/env python

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
Version build stamping script.

This module generates and inserts a patch component of the semantic version
stamp for Barbican, intended to ensure that a strictly monotonically increasing
version is produced for consecutive development releases. Some repositories
such as yum use this increasing semantic version to select the latest
package for installations.

This process may not be required if a bug in the 'pbr' library is fixed:
https://bugs.launchpad.net/pbr/+bug/1206730
"""
import os
import re

from datetime import datetime
from time import mktime


# Determine version of this application.
SETUP_FILE = 'setup.cfg'
VERSIONFILE = os.path.join(SETUP_FILE)
current_dir = os.getcwd()
if current_dir.endswith('bin'):
    VERSIONFILE = os.path.join('..', SETUP_FILE)


def get_patch():
    """Return a strictly monotonically increasing version patch.

    This method is providing the 'patch' component of the semantic version
    stamp for Barbican. It currently returns an epoch in seconds, but
    could use a build id from the build system.
    """
    dt = datetime.now()
    return int(mktime(dt.timetuple()))


def update_versionfile(patch):
    """Update the version information in setup.cfg per the provided patch.

    PBR will generate a version stamp based on the version attribute in the
    setup.cfg file, appending information such as git SHA code to it. To make
    this generated version friendly to packaging systems such as YUM, this
    function appends the provided patch to the base version. This function
    assumes the base version in setup.cfg is of the form 'xx.yy' such as
    '2014.2'. It will replace a third element found after this base with the
    provided patch.
    """
    version_regex = re.compile(r'(^\s*version\s*=\s*\w*\.\w*)(.*)')
    temp_name = VERSIONFILE + '~'
    with open(VERSIONFILE, 'r') as file_old:
        with open(temp_name, 'w') as file_new:
            for line in file_old:
                match = version_regex.match(line)
                if match:
                    file_new.write(''.join(
                        [match.group(1).strip(), '.', str(patch), '\n']))
                else:
                    file_new.write(line)

    # Replace the original setup.cfg with the modified one.
    os.rename(temp_name, VERSIONFILE)


if __name__ == '__main__':
    patch = get_patch()
    update_versionfile(patch)
