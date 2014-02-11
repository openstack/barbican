#!/bin/bash

# ---------------------
# Barbican Dependencies
# ---------------------

pushd $WORKSPACE/rpmbuild
export PYENV_VERSION=system

fpm -s python -t rpm -n python-falcon-barbican -v 0.1.6 falcon
fpm -s python -t rpm uWSGI
fpm -s python -t rpm -n python-wsgiref-barbican -v 0.1.2 wsgiref
fpm -s python -t rpm pysqlite
fpm -s python -t rpm -v 0.13.0 eventlet
fpm -s python -t rpm oslo.config
fpm -s python -t rpm oslo.messaging
fpm -s python -t rpm iso8601
fpm -s python -t rpm -v 3.0.8 kombu
fpm -s python -t rpm -n python-webob-barbican -v 1.2.3 webob
# --> # python-webob.noarch 0.9.6.1-3.el6 exists, but is incompatible
fpm -s python -t rpm -n python-pastedeploy-barbican -v 1.5.0 PasteDeploy
# --> python-paste-deploy 1.3.3-2.1.el6

# Rename keystoneclient due to odd dependency issue with yum repo.
fpm -s python -t rpm -n python-keystoneclient-barbican -v 0.4.1 python-keystoneclient

fpm -s python -t rpm -v 0.12 stevedore
fpm -s python -t rpm -n python-crypto pycrypto
# --> python-crypto 2.0.1-22.el6 exists, but is too old
fpm -s python -t rpm python-dateutil
# --> python-dateutil 1.4.1-6.el6 exists, but is incompatible
fpm -s python -t rpm -v 1.3.0 jsonschema
fpm -s python -t rpm -v 0.7.10 SQLAlchemy
# --> python-sqlalchemy 0.5.5-3.el6_2 exists, but is incompatible
fpm -s python -t rpm alembic

# ---------------------
# Indirect dependencies
# ---------------------

# oslo copy-pasta depends on
fpm -s python -t rpm netaddr
fpm -s python -t rpm Babel
fpm -s python -t rpm pytz

#oslo messaging depends on
fpm -s python -t rpm pyyaml

# python-alembic
fpm -s python -t rpm mako
# --> mako needs markupsafe
#     python-markupsafe  0.9.2-4.el6
# fpm -s python -t rpm markupsafe
fpm -s python -t rpm argparse

# python-eventlet
fpm -s python -t rpm greenlet

# python-falcon
fpm -s python -t rpm six
fpm -s python -t rpm ordereddict

# python-keystoneclient
# fpm -s python -t rpm six
# fpm -s python -t rpm argparse
fpm -s python -t rpm d2to1
fpm -s python -t rpm -v 0.5.21 pbr
# --> pbr needs setuptools-git
fpm -s python -t rpm setuptools-git
fpm -s python -t rpm prettytable
fpm -s python -t rpm requests
fpm -s python -t rpm simplejson

# python-kombu
fpm -s python -t rpm anyjson
fpm -s python -t rpm -v 1.3.3 amqp
# --> latest amqp is incompatible
fpm -s python -t rpm importlib
# fpm -s python -t rpm ordereddict

# oslo.config
# fpm -s python -t rpm argparse

# python-stevedore
# fpm -s python -t rpm argparse

# -------------------------------
# Upload to yum-repo.cloudkeep.io
# -------------------------------
scp *.rpm rpmbuild@yum-repo.cloudkeep.io:/var/www/html/centos/6/barbican/x86_64/
ssh rpmbuild@yum-repo.cloudkeep.io 'createrepo /var/www/html/centos/6/barbican/x86_64/'

popd
