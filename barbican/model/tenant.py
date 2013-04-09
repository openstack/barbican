# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
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

"""Generic Node base class for all workers that run on hosts."""

import logging
from base import Base
from sqlalchemy import Table, Column, String
from sqlalchemy import Integer, ForeignKey, Boolean
from sqlalchemy.orm import relationship, relation, backref
from sqlalchemy.ext.declarative import declarative_base, declared_attr


class Tenant(Base):
    """
    Tenants are users that wish to store secret information within
    Cloudkeep's Barbican.
    """

    logging.debug('In Tenant table setup')

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    # secrets = relationship('Secret', backref='tenant', lazy='dynamic')
    # secrets = relationship('Secret', secondary=_secrets)
    # secrets = relationship("Secret",
    #                     order_by="desc(Secret.name)",
    #                     primaryjoin="Secret.tenant_id==Tenant.id")

    def __init__(self, username):
        self.username = username

    def __init__(self, username, secrets=[]):
        self.username = username
        self.secrets = secrets

    def format(self):
        return {'id': self.id,
                'username': self.username}


class Secret(Base):
    """
    A secret is any information that needs to be stored and protected within
    Cloudkeep's Barbican.
    """

    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('secrets', order_by=id))
    # tenant = relationship(Tenant, primaryjoin=tenant_id == Tenant.id)

    # creates a bidirectional relationship
    # from Secret to Tenant it's Many-to-One
    # from Tenant to Secret it's One-to-Many
    # tenant = relation(Tenant, backref=backref('secret', order_by=id))

    def __init__(self, tenant_id, name):
        self.tenant_id = tenant_id
        self.name = name

    def format(self):
        return {'id': self.id,
                'name': self.username,
                'tenant_id': self.tenant_id}
