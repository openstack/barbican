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
from sqlalchemy import ForeignKey, DateTime, Boolean, Text, LargeBinary
from sqlalchemy.orm import relationship, object_mapper

from barbican.openstack.common import timeutils
from barbican.openstack.common import uuidutils
from barbican.common import utils

LOG = utils.getLogger(__name__)
BASE = declarative_base()


# Allowed entity states
class States(object):
    PENDING = 'PENDING'
    ACTIVE = 'ACTIVE'
    ERROR = 'ERROR'

    @classmethod
    def is_valid(self, state_to_test):
        """Tests if a state is a valid one."""
        return state_to_test in self.__dict__


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
        self.deleted = True
        self.deleted_at = timeutils.utcnow()
        self.save(session=session)

        self._do_delete_children(session)

    def _do_delete_children(self, session):
        """
        Sub-class hook: delete children relationships.
        """
        pass

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
        dict_fields = {'created': self.created_at,
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


class TenantSecret(BASE, ModelBase):
    """
    Represents an association between a Tenant and a Secret.
    """

    __tablename__ = 'tenant_secret'

    tenant_id = Column(String(36), ForeignKey('tenants.id'), primary_key=True)
    secret_id = Column(String(36), ForeignKey('secrets.id'), primary_key=True)
    role = Column(String(255))
    secret = relationship("Secret", backref="tenant_assocs")


class Tenant(BASE, ModelBase):
    """
    Represents a Tenant in the datastore

    Tenants are users that wish to store secret information within
    Cloudkeep's Barbican.
    """

    __tablename__ = 'tenants'

    keystone_id = Column(String(255), unique=True)

    orders = relationship("Order", backref="tenant")
    secrets = relationship("TenantSecret", backref="tenants")
    keks = relationship("KEKDatum", backref="tenant")

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
    expiration = Column(DateTime, default=None)
    algorithm = Column(String(255))
    bit_length = Column(Integer)
    cypher_type = Column(String(255))

    # TODO: Performance - Consider avoiding full load of all
    #   datum attributes here. This is only being done to support the
    #   building of the list of supported content types when secret
    #   metadata is retrieved.
    #   See barbican.api.resources.py::SecretsResource.on_get()
    encrypted_data = relationship("EncryptedDatum", lazy='joined')

    def __init__(self, parsed_request):
        """Creates secret from a dict."""
        super(Secret, self).__init__()

        self.name = parsed_request.get('name')
        self.expiration = parsed_request.get('expiration')
        self.algorithm = parsed_request.get('algorithm')
        self.bit_length = parsed_request.get('bit_length')
        self.cypher_type = parsed_request.get('cypher_type')

        self.status = States.ACTIVE

    def _do_delete_children(self, session):
        """
        Sub-class hook: delete children relationships.
        """
        for datum in self.encrypted_data:
            datum.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'secret_id': self.id,
                'name': self.name or self.id,
                'expiration': self.expiration,
                'algorithm': self.algorithm,
                'bit_length': self.bit_length,
                'cypher_type': self.cypher_type}


class EncryptedDatum(BASE, ModelBase):
    """
    Represents a the encrypted data for a Secret.
    """

    __tablename__ = 'encrypted_data'

    secret_id = Column(String(36), ForeignKey('secrets.id'),
                       nullable=False)
    kek_id = Column(String(36), ForeignKey('kek_data.id'),
                    nullable=False)
    content_type = Column(String(255))
    cypher_text = Column(LargeBinary)
    kek_meta_extended = Column(Text)
    kek_meta_tenant = relationship("KEKDatum")

    def __init__(self, secret=None, kek_datum=None):
        """Creates encrypted datum from a secret and KEK metadata."""
        super(EncryptedDatum, self).__init__()

        if secret:
            self.secret_id = secret.id

        if kek_datum:
            self.kek_id = kek_datum.id
            self.kek_meta_tenant = kek_datum

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'content_type': self.content_type}


class KEKDatum(BASE, ModelBase):
    """
    Represents the key encryption key (KEK) metadata associated with a process
    used to encrypt/decrypt secret information.

    When a secret is encrypted, in addition to the cypher text, the Barbican
    encryption process produces a KEK metadata object. The cypher text is
    stored via the EncryptedDatum model above, whereas the metadata is stored
    within this model. Decryption processes utilize this KEK metadata
    to decrypt the associated cypher text.

    Note that this model is intended to be agnostic to the specific means used
    to encrypt/decrypt the secret information, so please do not place vendor-
    specific attributes here.

    Note as well that each Tenant will have at most one 'active=True' KEKDatum
    instance at a time, representing the most recent KEK metadata instance
    to use for encryption processes performed on behalf of the Tenant.
    KEKDatum instances that are 'active=False' are associated to previously
    used encryption processes for the Tenant, that eventually should be
    rotated and deleted with the Tenant's active KEKDatum.
    """

    __tablename__ = 'kek_data'

    plugin_name = Column(String(255))
    kek_label = Column(String(255))

    tenant_id = Column(String(36), ForeignKey('tenants.id'),
                       nullable=False)

    active = Column(Boolean, nullable=False, default=True)
    bind_completed = Column(Boolean, nullable=False, default=False)
    algorithm = Column(String(255))
    bit_length = Column(Integer)
    mode = Column(String(255))
    plugin_meta = Column(Text)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'algorithm': self.algorithm}


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

    error_status_code = Column(String(16))
    error_reason = Column(String(255))

    secret_name = Column(String(255))
    secret_algorithm = Column(String(255))
    secret_bit_length = Column(Integer)
    secret_cypher_type = Column(String(255))
    secret_payload_content_type = Column(String(255), nullable=False)
    secret_expiration = Column(DateTime, default=None)

    secret_id = Column(String(36), ForeignKey('secrets.id'),
                       nullable=True)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        ret = {'secret': {'name': self.secret_name or self.secret_id,
                          'algorithm': self.secret_algorithm,
                          'bit_length': self.secret_bit_length,
                          'cypher_type': self.secret_cypher_type,
                          'expiration': self.secret_expiration,
                          'payload_content_type':
                          self.secret_payload_content_type},
               'secret_id': self.secret_id,
               'order_id': self.id}
        if self.error_status_code:
            ret['error_status_code'] = self.error_status_code
        if self.error_reason:
            ret['error_reason'] = self.error_reason
        return ret


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
