#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
    """Update the 'patch' version information per the provided patch."""
    temp_name = VERSIONFILE + '~'
    file_new = open(temp_name, 'w')
    try:
        with open(VERSIONFILE, 'r') as file_old:
            for line in file_old:
                if line.startswith('version ='):
                    subs = line.split('.')
                    if len(subs) <= 2:
                        file_new.write(''.join([line[:-1], '.',
                                                str(patch), '\n']))
                    else:
                        subs[2] = str(patch)
                        file_new.write('.'.join(subs))
                        if len(subs) == 3:
                            file_new.write('\n')
                else:
                    file_new.write(line)
    finally:
        file_new.close()
        os.rename(temp_name, VERSIONFILE)

if __name__ == '__main__':
    patch = get_patch()
    print 'patch: ', patch
    update_versionfile(patch)
