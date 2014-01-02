#!/bin/bash
set -o pipefail
flake8 barbican | tee flake8.log 
exit $?