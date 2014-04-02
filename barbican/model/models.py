# Copyright (c) 2013-2014 Rackspace, Inc.
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
import sqlalchemy as sa
from sqlalchemy.ext import compiler
from sqlalchemy.ext import declarative
from sqlalchemy import orm

from barbican.common import utils
from barbican.openstack.common import timeutils


LOG = utils.getLogger(__name__)
BASE = declarative.declarative_base()


# Allowed entity states
class States(object):
    PENDING = 'PENDING'
    ACTIVE = 'ACTIVE'
    ERROR = 'ERROR'

    @classmethod
    def is_valid(self, state_to_test):
        """Tests if a state is a valid one."""
        return state_to_test in self.__dict__


@compiler.compiles(sa.BigInteger, 'sqlite')
def compile_big_int_sqlite(type_, compiler, **kw):
    return 'INTEGER'


class ModelBase(object):
    """Base class for Nova and Barbican Models."""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    id = sa.Column(sa.String(36), primary_key=True,
                   default=utils.generate_uuid)

    created_at = sa.Column(sa.DateTime, default=timeutils.utcnow,
                           nullable=False)
    updated_at = sa.Column(sa.DateTime, default=timeutils.utcnow,
                           nullable=False, onupdate=timeutils.utcnow)
    deleted_at = sa.Column(sa.DateTime)
    deleted = sa.Column(sa.Boolean, nullable=False, default=False)

    status = sa.Column(sa.String(20), nullable=False, default=States.PENDING)

    def save(self, session=None):
        """Save this object."""
        # import api here to prevent circular dependency problem
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        session.add(self)
        session.flush()

    def delete(self, session=None):
        """Delete this object."""
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        self.deleted = True
        self.deleted_at = timeutils.utcnow()
        self.save(session=session)

        self._do_delete_children(session)

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
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
        self._i = iter(orm.object_mapper(self).sa.Columns)
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
    """Represents an association between a Tenant and a Secret."""

    __tablename__ = 'tenant_secret'

    tenant_id = sa.Column(sa.String(36), sa.ForeignKey('tenants.id'),
                          primary_key=True)
    secret_id = sa.Column(sa.String(36), sa.ForeignKey('secrets.id'),
                          primary_key=True)
    role = sa.Column(sa.String(255))
    secret = orm.relationship("Secret", backref="tenant_assocs")

    __table_args__ = (sa.UniqueConstraint('tenant_id', 'secret_id',
                                          name='_tenant_secret_uc'),)


class ContainerSecret(BASE):
    """Represents an association between a Container and a Secret."""

    __tablename__ = 'container_secret'

    container_id = sa.Column(sa.String(36), sa.ForeignKey('containers.id'),
                             primary_key=True)
    secret_id = sa.Column(sa.String(36), sa.ForeignKey('secrets.id'),
                          primary_key=True)
    name = sa.Column(sa.String(255), nullable=True)

    container = orm.relationship('Container',
                                 backref=orm.backref('container_secrets',
                                                     lazy='joined'))
    secrets = orm.relationship('Secret',
                               backref=orm.backref('container_secrets'))

    __table_args__ = (sa.UniqueConstraint('container_id', 'secret_id', 'name',
                                          name='_container_secret_name_uc'),)


class Tenant(BASE, ModelBase):
    """Represents a Tenant in the datastore.

    Tenants are users that wish to store secret information within
    Cloudkeep's Barbican.
    """

    __tablename__ = 'tenants'

    keystone_id = sa.Column(sa.String(255), unique=True)

    orders = orm.relationship("Order", backref="tenant")
    secrets = orm.relationship("TenantSecret", backref="tenants")
    keks = orm.relationship("KEKDatum", backref="tenant")
    containers = orm.relationship("Container", backref="tenant")

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'keystone_id': self.keystone_id}


class Secret(BASE, ModelBase):
    """Represents a Secret in the datastore.

    Secrets are any information Tenants wish to store within
    Cloudkeep's Barbican, though the actual encrypted data
    is stored in one or more EncryptedData entities on behalf
    of a Secret.
    """

    __tablename__ = 'secrets'

    name = sa.Column(sa.String(255))
    expiration = sa.Column(sa.DateTime, default=None)
    algorithm = sa.Column(sa.String(255))
    bit_length = sa.Column(sa.Integer)
    mode = sa.Column(sa.String(255))

    # TODO(jwood): Performance - Consider avoiding full load of all
    #   datum attributes here. This is only being done to support the
    #   building of the list of supported content types when secret
    #   metadata is retrieved.
    #   See barbican.api.resources.py::SecretsResource.on_get()
    encrypted_data = orm.relationship("EncryptedDatum", lazy='joined')

    def __init__(self, parsed_request=None):
        """Creates secret from a dict."""
        super(Secret, self).__init__()

        if parsed_request:
            self.name = parsed_request.get('name')
            self.expiration = parsed_request.get('expiration')
            self.algorithm = parsed_request.get('algorithm')
            self.bit_length = parsed_request.get('bit_length')
            self.mode = parsed_request.get('mode')

        self.status = States.ACTIVE

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for datum in self.encrypted_data:
            datum.delete(session)

        for secret_ref in self.container_secrets:
                session.delete(secret_ref)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'secret_id': self.id,
                'name': self.name or self.id,
                'expiration': self.expiration,
                'algorithm': self.algorithm,
                'bit_length': self.bit_length,
                'mode': self.mode}


class EncryptedDatum(BASE, ModelBase):
    """Represents a the encrypted data for a Secret."""

    __tablename__ = 'encrypted_data'

    secret_id = sa.Column(sa.String(36), sa.ForeignKey('secrets.id'),
                          nullable=False)
    kek_id = sa.Column(sa.String(36), sa.ForeignKey('kek_data.id'),
                       nullable=False)
    content_type = sa.Column(sa.String(255))

    # TODO(jwood) Why LargeBinary on Postgres (BYTEA) not work correctly?
    cypher_text = sa.Column(sa.Text)

    kek_meta_extended = sa.Column(sa.Text)
    kek_meta_tenant = orm.relationship("KEKDatum")

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
    """Key encryption key (KEK) metadata model.

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

    plugin_name = sa.Column(sa.String(255))
    kek_label = sa.Column(sa.String(255))

    tenant_id = sa.Column(sa.String(36), sa.ForeignKey('tenants.id'),
                          nullable=False)

    active = sa.Column(sa.Boolean, nullable=False, default=True)
    bind_completed = sa.Column(sa.Boolean, nullable=False, default=False)
    algorithm = sa.Column(sa.String(255))
    bit_length = sa.Column(sa.Integer)
    mode = sa.Column(sa.String(255))
    plugin_meta = sa.Column(sa.Text)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'algorithm': self.algorithm}


class Order(BASE, ModelBase):
    """Represents an Order in the datastore.

    Orders are requests for Barbican to create secret information,
    ranging from simple AES key generation requests to automated
    requests to Certificate Authorities to generate SSL certificates.
    """

    __tablename__ = 'orders'

    tenant_id = sa.Column(sa.String(36), sa.ForeignKey('tenants.id'),
                          nullable=False)

    error_status_code = sa.Column(sa.String(16))
    error_reason = sa.Column(sa.String(255))

    secret_name = sa.Column(sa.String(255))
    secret_algorithm = sa.Column(sa.String(255))
    secret_bit_length = sa.Column(sa.Integer)
    secret_mode = sa.Column(sa.String(255))
    secret_payload_content_type = sa.Column(sa.String(255), nullable=False)
    secret_expiration = sa.Column(sa.DateTime, default=None)

    secret_id = sa.Column(sa.String(36), sa.ForeignKey('secrets.id'),
                          nullable=True)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        ret = {'secret': {'name': self.secret_name or self.secret_id,
                          'algorithm': self.secret_algorithm,
                          'bit_length': self.secret_bit_length,
                          'mode': self.secret_mode,
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


class Container(BASE, ModelBase):
    """Represents a Container for Secrets in the datastore.

    Containers store secret references. Containers are owned by Tenants.
    Containers can be generic or have a predefined type. Predefined typed
    containers allow users to store structured key relationship
    inside Barbican.
    """

    __tablename__ = 'containers'

    name = sa.Column(sa.String(255))
    type = sa.Column(sa.Enum('generic', 'rsa', name='container_types'))
    tenant_id = sa.Column(sa.String(36), sa.ForeignKey('tenants.id'),
                          nullable=False)

    def __init__(self, parsed_request=None):
        """Creates a Container entity from a dict."""
        super(Container, self).__init__()

        if parsed_request:
            self.name = parsed_request.get('name')
            self.type = parsed_request.get('type')
            self.status = States.ACTIVE

            secret_refs = parsed_request.get('secret_refs')
            if secret_refs:
                for secret_ref in parsed_request.get('secret_refs'):
                    container_secret = ContainerSecret()
                    container_secret.name = secret_ref.get('name')
                    #TODO: (hgedikli) move this into a common location
                    #TODO: (hgedikli) validate provided url
                    #TODO: (hgedikli) parse out secret_id with regex
                    secret_id = secret_ref.get('secret_ref')
                    if secret_id.endswith('/'):
                        secret_id = secret_id.rsplit('/', 2)[1]
                    elif '/' in secret_id:
                        secret_id = secret_id.rsplit('/', 1)[1]
                    else:
                        secret_id = secret_id
                    container_secret.secret_id = secret_id
                    self.container_secrets.append(container_secret)

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for container_secret in self.container_secrets:
            session.delete(container_secret)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'container_id': self.id,
                'name': self.name or self.id,
                'type': self.type,
                'secret_refs': [
                    {
                        'secret_id': container_secret.secret_id,
                        'name': container_secret.name
                        if hasattr(container_secret, 'name') else None
                    } for container_secret in self.container_secrets]}

# Keep this tuple synchronized with the models in the file
MODELS = [TenantSecret, Tenant, Secret, EncryptedDatum, Order, Container,
          ContainerSecret]


def register_models(engine):
    """Creates database tables for all models with the given engine."""
    LOG.debug("Models: {0}".format(repr(MODELS)))
    for model in MODELS:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """Drops database tables for all models with the given engine."""
    for model in MODELS:
        model.metadata.drop_all(engine)
