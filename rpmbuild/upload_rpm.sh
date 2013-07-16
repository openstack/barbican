#!/bin/bash

echo "Uploading RPMs to yum-repo.cloudkeep.io"

pushd $PWD
scp rpmbuild/RPMS/noarch/*.rpm rpmbuild@yum-repo.cloudkeep.io:/var/www/html/centos/6/barbican/x86_64/
ssh rpmbuild@yum-repo.cloudkeep.io 'createrepo /var/www/html/centos/6/barbican/x86_64/'
popd
