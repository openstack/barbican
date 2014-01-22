#!/bin/bash

CONFIG_DIR=/etc/barbican
DB_DIR=/var/lib/barbican

# VIRTUAL_ENV is set by virtualenv on activate. If VIRTUAL_ENV is not,
# available, it attempts to fallback on pyenv for the python environment path.
VENV_DIR=${VIRTUAL_ENV:-`pyenv prefix`}

LOCAL_CONFIG_DIR=./etc/barbican
if [ ! -d $LOCAL_CONFIG_DIR ];
then
  LOCAL_CONFIG_DIR=../etc/barbican
fi
LOCAL_CONFIG=$LOCAL_CONFIG_DIR/barbican-api.conf

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo 'DIR: '$DIR

start_barbican()
{
    # Start barbican server up.
    #   Note: Add ' --stats :9314' to run a stats server on port 9314
    echo "Starting barbican..."
    uwsgi --master --emperor $CONFIG_DIR/vassals -H $VENV_DIR
}

stop_barbican()
{
    echo "Stopping barbican..."
    killall -KILL uwsgi
}

install_barbican()
{
    # Copy conf file to home directory so oslo.config can find it
    cp $LOCAL_CONFIG ~

    # Copy the other config files to the /etc location
    if [ ! -d $CONFIG_DIR ];
    then
      sudo mkdir -p $CONFIG_DIR
      sudo chown $USER $CONFIG_DIR
    fi
    cp -rf $LOCAL_CONFIG_DIR/* $CONFIG_DIR/

    # Create a SQLite db location.
    if [ ! -d $DB_DIR ];
    then
      sudo mkdir -p $DB_DIR
      sudo chown $USER $DB_DIR
    fi

    # Install Python dependencies
    pip install -r requirements.txt
    pip install -r test-requirements.txt

    # Install uWSGI
    pip install uwsgi

    # Install source code into the Python path as if packaged.
    pip install -e .

    # If using pyenv, rehash now.
    hash pyenv &> /dev/null
    if [ $? -eq 0 ]; then
       pyenv rehash
    fi

    # Run unit tests
    nosetests

    start_barbican
}


case "$1" in
  install)
    install_barbican
    ;;
  start)
    start_barbican
    ;;
  stop)
    stop_barbican
    ;;
  restart)
    stop_barbican
    sleep 5
    start_barbican
    ;;

  *)
    echo "Usage: barbican.sh  {install|start|stop|restart}"
    exit 1
esac
