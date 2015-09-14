#!/usr/bin/env bash

set -o pipefail

TESTRARGS=$1
python setup.py testr --testr-args="--subunit $TESTRARGS" | subunit-trace --no-failure-debug -f
retval=$?
echo -e "\nSlowest Tests:\n"
testr slowest
exit $retval