# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

setup(
    name = 'barbican',
    version = '0.1',
    description = '',
    author = 'Project Barbican',
    author_email = '',
    install_requires = [
        "falcon",
        "mock",
        "wsgiref",
        "uWSGI",
        "pymongo",
    ],
    test_suite = 'barbican.tests',
    zip_safe = False,
    include_package_data = True,
    packages = find_packages(exclude=['ez_setup'])
)
