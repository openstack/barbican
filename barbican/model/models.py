# Copyright (c) 2013 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Defines database models for Barbican
"""

from sqlalchemy import Column, Integer, String, BigInteger
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey, DateTime, Boolean, Text
from sqlalchemy.orm import relationship, backref, object_mapper
from sqlalchemy import Index, UniqueConstraint

from barbican.openstack.common import timeutils
from barbican.openstack.common import uuidutils
from barbican.openstack.common import jsonutils as json
from barbican.common import utils

LOG = utils.getLogger(__name__)
BASE = declarative_base()


# Allowed entity states
class States(object):
    PENDING = 'PENDING'
    ACTIVE = 'ACTIVE'


@compiles(BigInteger, 'sqlite')
def compile_big_int_sqlite(type_, compiler, **kw):
    return 'INTEGER'


class ModelBase(object):
    """Base class for Nova and Barbican Models"""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    id = Column(String(36), primary_key=True, default=uuidutils.generate_uuid)

    created_at = Column(DateTime, default=timeutils.utcnow,
                        nullable=False)
    updated_at = Column(DateTime, default=timeutils.utcnow,
                        nullable=False, onupdate=timeutils.utcnow)
    deleted_at = Column(DateTime)
    deleted = Column(Boolean, nullable=False, default=False)

    status = Column(String(20), nullable=False, default=States.PENDING)

    def save(self, session=None):
        """Save this object"""
        # import api here to prevent circular dependency problem
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        session.add(self)
        session.flush()

    def delete(self, session=None):
        """Delete this object"""
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        session.delete(self)

        #TODO: Soft delete instead?
        # self.deleted = True
        # self.deleted_at = timeutils.utcnow()
        # self.save(session=session)

    def update(self, values):
        """dict.update() behaviour."""
        for k, v in values.iteritems():
            self[k] = v

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __iter__(self):
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n, getattr(self, n)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def to_dict(self):
        return self.__dict__.copy()

    def to_dict_fields(self):
        """Returns a dictionary of just the db fields of this entity."""
        dict_fields = {'id': self.id,
                       'created': self.created_at,
                       'updated': self.updated_at,
                       'status': self.status}
        if self.deleted_at:
            dict_fields['deleted'] = self.deleted_at
        if self.deleted:
            dict_fields['is_deleted'] = True
        dict_fields.update(self._do_extra_dict_fields())
        return dict_fields

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {}


# Association table between Tenants and Secrets
#tenant_secret_table = Table('tenant_secret', BASE.metadata,
#    Column('tenant_id', Integer, ForeignKey('tenants.id')),
#    Column('secret_id', Integer, ForeignKey('secrets.id')),
#    Column('role', Text)
#)


class TenantSecret(BASE, ModelBase):
    __tablename__ = 'tenant_secret'
    
    tenant_id = Column(Integer, ForeignKey('tenants.id'), primary_key=True)
    secret_id = Column(Integer, ForeignKey('secrets.id'), primary_key=True)
    role = Column(String(255))
    secret = relationship("Secret")


class Tenant(BASE, ModelBase):
    """
    Represents a Tenant in the datastore

    Tenants are users that wish to store secret information within
    Cloudkeep's Barbican.
    """

    __tablename__ = 'tenants'

    keystone_id = Column(String(255))

    orders = relationship("Order")
    secrets = relationship("TenantSecret")

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'keystone_id': self.keystone_id}


class Secret(BASE, ModelBase):
    """
    Represents a Secret in the datastore

    Secrets are any information Tenants wish to store within
    Cloudkeep's Barbican, though the actual encrypted data
    is stored in one or more EncryptedData entities on behalf
    of a Secret.
    """

    __tablename__ = 'secrets'

    name = Column(String(255))
    expiration = Column(DateTime, default=timeutils.utcnow,
                        nullable=False)

    encrypted_data = relationship("EncryptedDatum")

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'name': self.name,
                'expiration': self.expiration}


class EncryptedDatum(BASE, ModelBase):
    """
    Represents a the encrypted data for a Secret.
    """

    __tablename__ = 'encrypted_data'

    secret_id = Column(String(36), ForeignKey('secrets.id'),
                    nullable=False)

    mime_type = Column(String(255))
    cypher_text = Column(Text)
    kek_metadata = Column(Text)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'name': self.name,
                'mime_type': self.mime_type,
                'cypher_text': self.secret}


class Order(BASE, ModelBase):
    """
    Represents an Order in the datastore

    Orders are requests for Barbican to create secret information,
    ranging from simple AES key generation requests to automated
    requests to Certificate Authorities to generate SSL certificates.
    """

    __tablename__ = 'orders'

    tenant_id = Column(String(36), ForeignKey('tenants.id'),
                       nullable=False)
#    tenant = relationship(Tenant, backref=backref('csr_assocs'))

    secret_name = Column(String(255))
    secret_mime_type = Column(String(255))
    secret_expiration = Column(DateTime, default=timeutils.utcnow,
                        nullable=False)

    secret_id = Column(String(36), ForeignKey('secrets.id'),
                       nullable=True)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'secret_name': self.secret_name,
                'secret_mime_type': self.secret_mime_type,
                'secret_expiration': self.secret_expiration,
                'secret_id': self.secret_id,
                'tenant_id': self.tenant_id}


# Keep this tuple synchronized with the models in the file
MODELS = [TenantSecret, Tenant, Secret, EncryptedDatum, Order]


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    LOG.debug("Models: {0}".format(repr(MODELS)))
    for model in MODELS:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    for model in MODELS:
        model.metadata.drop_all(engine)
