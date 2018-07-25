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
LOCAL_CONFIG=$LOCAL_CONFIG_DIR/barbican.conf

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo 'DIR: '$DIR

debug_barbican()
{
    #   Start barbican server in debug mode.
    #   Note: for Eclipse IDE users
    #   Make sure PYTHONPATH is set with pydev
    #   export PYTHONPATH=/<eclipse_home>/plugins/org.python.pydev_2.8.2.2013090511/pysrc"
    #   Note: for Pycharm IDE users
    #   Follow the instruction in link below
    #   https://github.com/cloudkeep/barbican/wiki/Developer-Guide-for-Contributors#debugging-using-pycharm
    #   Following are two commands to start barbican in debug mode
    #   (1) ./barbican.sh debug
    #   (2) ./barbican.sh debug --pydev-debug-host localhost  --pydev-debug-port 5678

    if [ -z $3 ] ;
    then
        debug_host=localhost
    else
        debug_host=$3
    fi

    if [ -z $5 ] ; then
       debug_port=5678
    else
       debug_port=$5
    fi

    echo "Starting barbican in debug mode ..." --pydev-debug-host $debug_host --pydev-debug-port $debug_port
    PYDEV_DEBUG_PARAM="--env PYDEV_DEBUG_HOST=$debug_host --env PYDEV_DEBUG_PORT=$debug_port"

    uwsgi --master --emperor $CONFIG_DIR/vassals -H $VENV_DIR $PYDEV_DEBUG_PARAM
}

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

    # Run unit tests
    stestr run

    start_barbican
}


case "$1" in
  install)
    install_barbican
    ;;
  debug)
    debug_barbican $*
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
    echo "Usage: barbican.sh  {install|start|stop|debug <debug_params>|restart}"
    echo "where debug_params are: --pydev-debug-host <host> --pydev-debug-port <port>, <host> defaults to 'localhost' and <port> defaults to '5678'"
    exit 1
esac
