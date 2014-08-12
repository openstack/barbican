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

import pbr.version


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

    PBR will generate a version stamp per the docstring of _get_pbr_version()
    below, which then stamps the version on source tarballs used for
    packaging. This version stamp is not packaging friendly as it is not
    monotonically increasing alphabetically. If a 'version' attribute is added
    to setup.cfg, PBR will override the output major, minor and build
    versions of the stamped version. By injecting a patch into this version
    structure per this function, the desired monotonic version number can
    be created.
    """
    temp_name = VERSIONFILE + '~'
    with open(VERSIONFILE, 'r') as file_old:
        with open(temp_name, 'w') as file_new:
            for line in file_old:
                if line.startswith('[metadata]'):
                    file_new.write(line)

                    # Add a 'version =' line to override the version info.
                    base, extension = _get_pbr_version()
                    if extension:
                        file_new.write('version = '
                                       '{0}.{1}.{2}\n'.format(base, patch,
                                                              extension))
                    else:
                        file_new.write('version = {0}.{1}\n'.format(base, patch))

                elif line.startswith('version'):
                    raise ValueError("The file 'setup.cfg' must not already "
                                     "contain a 'version =' line.")
                else:
                    file_new.write(line)

    # Replace the original setup.cfg with the modified one.
    os.rename(temp_name, VERSIONFILE)


def _get_pbr_version():
    """Returns the version stamp from PBR.

    PBR versions are either of the form yyyy.s.bm.devx.gitsha (for milestone
    releases) or yyyy.s.devx.gitsha for series releases. This function returns
    the base part (yyyy.s) and the optional extension without the devx.gitsha
    portions (so either None or bm). The devx.gitsha portion should not be
    returned, as it will be supplied by PBR as part of its version generation
    process when 'python setup.py sdist' is later invoked.
    """
    version_info = pbr.version.VersionInfo('barbican')
    base = version_info.version_string()
    full = version_info.release_string()
    if base != full:
        extension = _trim_base_from_version(full, base)
        if _is_milestone_release(extension):
            return base, extension.split('.')[0]

    return base, None


def _trim_base_from_version(full_version, base_version):
    """Removes the base version information from the full version."""
    return full_version[len(base_version) + 1:]


def _is_milestone_release(extension):
    """Tests if extension corresponds to an OpenStack milestone release."""
    return extension.startswith('b')


if __name__ == '__main__':
    patch = get_patch()
    update_versionfile(patch)
