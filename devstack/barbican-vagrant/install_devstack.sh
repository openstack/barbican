#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y python-pip python-dev libffi-dev libssl-dev git

git clone https://github.com/openstack-dev/devstack.git
git clone https://github.com/openstack/barbican.git

cp barbican/devstack/local.conf.example devstack/local.conf

sudo cp -R devstack/ /opt/stack/
sudo chown -R vagrant:vagrant /opt/stack/

echo "export SERVICE_HOST=\"localhost\"" >> .bashrc