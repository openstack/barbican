#!/bin/bash

# ---------------------
# Barbican Dependencies
# ---------------------

pushd $WORKSPACE/rpmbuild
export PYENV_VERSION=system

fpm -s python -t rpm uWSGI
fpm -s python -t rpm cryptography

popd
