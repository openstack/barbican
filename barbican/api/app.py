# Copyright 2010-2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
API application handler for Cloudkeep's Barbican
"""


import falcon

from barbican.api.resources import VersionResource
from barbican.api.resources import TenantsResource, TenantResource
from barbican.api.resources import SecretsResource, SecretResource
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import scoped_session, sessionmaker
from barbican.model.tenant import Base

# TBD: Remove this odd dependency
from config import config


"""
Locally scoped db session
"""
_Session = scoped_session(sessionmaker())
_engine = None


def db_session():
    return _Session


def _engine_from_config(configuration):
    configuration = dict(configuration)
    url = configuration.pop('url')

    return create_engine(url, **configuration)


def init_tenant_model():
    _engine = _engine_from_config(config['sqlalchemy'])
    from barbican.model.tenant import Tenant, Secret
    Base.metadata.create_all(_engine)
    _Session.bind = _engine


# Initialize the data model
init_tenant_model()

# test the database out
#from barbican.model.tenant import Tenant, Secret
#jw_user = Tenant("jwoody")
#_Session.add(jw_user)

# select all and print out all the results sorted by id
#for instance in _Session.query(Tenant).order_by(Tenant.id):
#    print instance.username

# Resources
versions = VersionResource()
tenants = TenantsResource(db_session())
tenant = TenantResource(db_session())
secrets = SecretsResource(db_session())
secret = SecretResource(db_session())

# Routing
application = falcon.API()
api = application
api.add_route('/', versions)
api.add_route('/v1', tenants)
api.add_route('/v1/{tenant_id}', tenant)
api.add_route('/v1/{tenant_id}/secrets', secrets)
api.add_route('/v1/{tenant_id}/secrets/{secret_id}', secret)
