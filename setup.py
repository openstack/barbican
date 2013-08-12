#!/usr/bin/python
# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
try:
    from setuptools import setup, find_packages
    from setuptools.command.sdist import sdist
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
    from setuptools.command.sdist import sdist

# Determine version of this application.
# TBD: Revisit version flows and processing once integrating with OpenStack,
#   see glance setup.py
PKG = "barbican"
VERSIONFILE = os.path.join(PKG, "version.py")
version = "unknown"
try:
    version_file = open(VERSIONFILE, "r")
    for line in version_file:
        if '__version__' in line:
            version = line.split("'")[1]
            break
except EnvironmentError:
    pass  # Okay, there is no version file.


class local_sdist(sdist):
    """Customized sdist hook - builds the ChangeLog file from VC first"""

    def run(self):
        sdist.run(self)

cmdclass = {'sdist': local_sdist}

# TDB: Revisit sphinx documentation needs once move to OpenStack...
#   see barbican setup.py

setup(
    name='barbican',
    version=version,
    description='The Barbican project provides a service for storing '
                'sensitive client information such as encryption keys',
    license='Apache License (2.0)',
    author='OpenStack',
    author_email='john.wood@rackspace.com',
    url='http://barbican.openstack.org/',
    packages=find_packages(exclude=['bin']),
    test_suite='nose.collector',
    cmdclass=cmdclass,
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Environment :: No Input/Output (Daemon)',
    ],
    scripts=['bin/barbican-all'],
    py_modules=[],
    entry_points="""
    [barbican.crypto.plugin]
    p11_crypto = barbican.crypto.p11_crypto:P11CryptoPlugin
    simple_crypto = barbican.crypto.plugin:SimpleCryptoPlugin

    [barbican.test.crypto.plugin]
    test_crypto = barbican.tests.crypto.test_plugin:TestCryptoPlugin
    """
)
