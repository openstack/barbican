#!/bin/bash

# ---------------------
# Barbican Dependencies
# ---------------------

pushd $PWD/rpmbuild

fpm -s python -t rpm falcon
fpm -s python -t rpm uWSGI
fpm -s python -t rpm pysqlite
fpm -s python -t rpm eventlet
fpm -s python -t rpm oslo.config
fpm -s python -t rpm iso8601
fpm -s python -t rpm kombu
fpm -s python -t rpm webob
# --> # python-webob.noarch 0.9.6.1-3.el6 exists, but is incompatible
# fpm -s python -t rpm PasteDeploy
# --> python-paste-deploy 1.3.3-2.1.el6
fpm -s python -t rpm Celery
fpm -s python -t rpm python-keystoneclient
fpm -s python -t rpm stevedore
fpm -s python -t rpm pycrypto
# --> python-crypto 2.0.1-22.el6 exists, but is too old
fpm -s python -t rpm python-dateutil
# --> python-dateutil 1.4.1-6.el6 exists, but is incompatible
fpm -s python -t rpm jsonschema
fpm -s python -t rpm SQLAlchemy
# --> python-sqlalchemy 0.5.5-3.el6_2 exists, but is incompatible
fpm -s python -t rpm alembic
# fpm -s python -t rpm psycopg2
# --> python-psycopg2 2.0.14-2.el6

# ---------------------
# Indirect dependencies
# ---------------------

# python-alembic
fpm -s python -t rpm mako
# --> mako needs markupsafe
#     python-markupsafe  0.9.2-4.el6
# fpm -s python -t rpm markupsafe
fpm -s python -t rpm argparse

# python-celery
fpm -s python -t rpm billiard

# python-eventlet
fpm -s python -t rpm greenlet

# python-falcon
fpm -s python -t rpm six
fpm -s python -t rpm ordereddict

# python-keystoneclient
# fpm -s python -t rpm six
# fpm -s python -t rpm argparse
fpm -s python -t rpm d2to1
fpm -s python -t rpm pbr
# --> pbr needs setuptools-git
fpm -s python -t rpm setuptools-git
fpm -s python -t rpm prettytable
fpm -s python -t rpm requests
fpm -s python -t rpm simplejson

# python-kombu
fpm -s python -t rpm anyjson
fpm -s python -t rpm -v 1.0.12 amqp
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
