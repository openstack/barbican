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
import hashlib

from oslo_serialization import jsonutils as json
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.ext import compiler
from sqlalchemy.ext import declarative
from sqlalchemy import orm
from sqlalchemy.orm import collections as col
from sqlalchemy import types as sql_types

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u

BASE = declarative.declarative_base()
ERROR_REASON_LENGTH = 255
SUB_STATUS_LENGTH = 36
SUB_STATUS_MESSAGE_LENGTH = 255


# Allowed entity states
class States(object):
    PENDING = 'PENDING'
    ACTIVE = 'ACTIVE'
    ERROR = 'ERROR'

    @classmethod
    def is_valid(cls, state_to_test):
        """Tests if a state is a valid one."""
        return state_to_test in cls.__dict__


class OrderType(object):
    KEY = 'key'
    ASYMMETRIC = 'asymmetric'
    CERTIFICATE = 'certificate'

    @classmethod
    def is_valid(cls, order_type):
        """Tests if a order type is a valid one."""
        return order_type in cls.__dict__


class OrderStatus(object):
    def __init__(self, id, message):
        self.id = id
        self.message = message


@compiler.compiles(sa.BigInteger, 'sqlite')
def compile_big_int_sqlite(type_, compiler, **kw):
    return 'INTEGER'


class JsonBlob(sql_types.TypeDecorator):
    """JsonBlob is custom type for fields which need to store JSON text."""
    impl = sa.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value


class ModelBase(object):
    """Base class for Nova and Barbican Models."""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = {
        "created_at", "updated_at", "deleted_at", "deleted",
    }

    id = sa.Column(
        sa.String(36),
        primary_key=True,
        default=utils.generate_uuid)
    created_at = sa.Column(
        sa.DateTime,
        default=timeutils.utcnow,
        nullable=False)
    updated_at = sa.Column(
        sa.DateTime,
        default=timeutils.utcnow,
        nullable=False,
        onupdate=timeutils.utcnow)
    deleted_at = sa.Column(sa.DateTime)
    deleted = sa.Column(sa.Boolean, nullable=False, default=False)
    status = sa.Column(sa.String(20), nullable=False, default=States.PENDING)

    def save(self, session=None):
        """Save this object."""
        # import api here to prevent circular dependency problem
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        # if model is being created ensure that created/updated are the same
        if self.id is None:
            self.created_at = timeutils.utcnow()
            self.updated_at = self.created_at
        session.add(self)
        session.flush()

    def delete(self, session=None):
        """Delete this object."""
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        self._do_delete_children(session)
        session.delete(self)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        pass

    def update(self, values):
        """dict.update() behaviour."""
        for k, v in values.items():
            self[k] = v

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __iter__(self):
        self._i = iter(orm.object_mapper(self).sa.Columns)
        return self

    def next(self):
        n = next(self._i).name
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

        if self.created_at:
            created_at = self.created_at.isoformat()
        else:
            created_at = self.created_at

        if self.updated_at:
            updated_at = self.updated_at.isoformat()
        else:
            updated_at = self.updated_at

        dict_fields = {
            'created': created_at,
            'updated': updated_at,
            'status': self.status
        }

        if self.deleted_at:
            dict_fields['deleted_at'] = self.deleted_at.isoformat()
        if self.deleted:
            dict_fields['deleted'] = True
        dict_fields.update(self._do_extra_dict_fields())
        return dict_fields

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {}

    def _iso_to_datetime(self, expiration):
        """Convert ISO formatted string to datetime."""
        if isinstance(expiration, str):
            expiration_iso = timeutils.parse_isotime(expiration.strip())
            expiration = timeutils.normalize_time(expiration_iso)

        return expiration


class SoftDeleteMixIn(object):
    """Mix-in class that adds soft delete functionality."""

    def delete(self, session=None):
        """Delete this object."""
        import barbican.model.repositories
        session = session or barbican.model.repositories.get_session()
        self.deleted = True
        self.deleted_at = timeutils.utcnow()
        self.save(session=session)

        self._do_delete_children(session)


class ContainerSecret(BASE, SoftDeleteMixIn, ModelBase):
    """Represents an association between a Container and a Secret."""

    __tablename__ = 'container_secret'

    name = sa.Column(sa.String(255), nullable=True)
    container_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('containers.id'),
        index=True,
        nullable=False)
    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=False)

    # Eager load this relationship via 'lazy=False'.
    container = orm.relationship(
        'Container',
        back_populates='container_secrets',
        primaryjoin='and_(ContainerSecret.container_id == Container.id, ContainerSecret.deleted != True)',  # noqa: E501
        lazy=False,
    )
    secrets = orm.relationship(
        'Secret',
        back_populates='container_secrets',
        primaryjoin='and_(ContainerSecret.secret_id == Secret.id, ContainerSecret.deleted != True)',  # noqa: E501
        lazy=False,
    )

    __table_args__ = (
        sa.UniqueConstraint(
            'container_id', 'secret_id', 'name',
            name='_container_secret_name_uc'),
    )

    def __init__(self, check_exc=True):
        super(ContainerSecret, self).__init__()


class Project(BASE, SoftDeleteMixIn, ModelBase):
    """Represents a Project in the datastore.

    Projects are users that wish to store secret information within Barbican.
    """

    __tablename__ = 'projects'

    external_id = sa.Column(sa.String(255), unique=True)

    orders = orm.relationship('Order', back_populates='project')
    secrets = orm.relationship('Secret', back_populates='project')
    keks = orm.relationship('KEKDatum', back_populates='project')
    containers = orm.relationship('Container', back_populates='project')
    cas = orm.relationship(
        'ProjectCertificateAuthority',
        back_populates='project')
    project_quotas = orm.relationship(
        'ProjectQuotas',
        back_populates='project')
    preferred_ca = orm.relationship(
        'PreferredCertificateAuthority',
        back_populates='project')
    preferred_secret_store = orm.relationship(
        'ProjectSecretStore',
        back_populates='project')

    def __init__(self, check_exc=True):
        super(Project, self).__init__()

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'external_id': self.external_id}


class Secret(BASE, SoftDeleteMixIn, ModelBase):
    """Represents a Secret in the datastore.

    Secrets are any information Projects wish to store within
    Barbican, though the actual encrypted data is stored in one
    or more EncryptedData entities on behalf of a Secret.
    """

    __tablename__ = 'secrets'

    name = sa.Column(sa.String(255))
    secret_type = sa.Column(
        sa.String(255),
        server_default=utils.SECRET_TYPE_OPAQUE)
    expiration = sa.Column(sa.DateTime, default=None)
    algorithm = sa.Column(sa.String(255))
    bit_length = sa.Column(sa.Integer)
    mode = sa.Column(sa.String(255))
    creator_id = sa.Column(sa.String(255))
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='secrets_project_fk'),
        index=True,
        nullable=False)

    # TODO(jwood): Performance - Consider avoiding full load of all
    #   datum attributes here. This is only being done to support the
    #   building of the list of supported content types when secret
    #   metadata is retrieved.
    #   See barbican.api.resources.py::SecretsResource.on_get()
    # Eager load this relationship via 'lazy=False'.
    encrypted_data = orm.relationship("EncryptedDatum", lazy=False)
    project = orm.relationship('Project', back_populates='secrets')
    container_secrets = orm.relationship(
        "ContainerSecret",
        primaryjoin='and_(ContainerSecret.secret_id==Secret.id, ContainerSecret.deleted!=True)',  # noqa: E501
        back_populates='secrets',
        lazy=False)
    secret_store_metadata = orm.relationship(
        "SecretStoreMetadatum",
        collection_class=col.attribute_mapped_collection('key'),
        back_populates="secret",
        cascade="all, delete-orphan",
        cascade_backrefs=False)
    secret_user_metadata = orm.relationship(
        "SecretUserMetadatum",
        collection_class=col.attribute_mapped_collection('key'),
        back_populates="secret",
        cascade="all, delete-orphan",
        cascade_backrefs=False)
    consumers = orm.relationship(
        "SecretConsumerMetadatum",
        back_populates="secret",
        cascade="all, delete-orphan",
        cascade_backrefs=False)
    secret_acls = orm.relationship(
        "SecretACL",
        back_populates="secret",
        lazy=False)

    def __init__(self, parsed_request=None, check_exc=True):
        """Creates secret from a dict."""
        super(Secret, self).__init__()

        if parsed_request:
            self.name = parsed_request.get('name')
            self.secret_type = parsed_request.get(
                'secret_type',
                utils.SECRET_TYPE_OPAQUE)
            expiration = self._iso_to_datetime(parsed_request.get
                                               ('expiration'))
            self.expiration = expiration
            self.algorithm = parsed_request.get('algorithm')
            self.bit_length = parsed_request.get('bit_length')
            self.mode = parsed_request.get('mode')
            self.creator_id = parsed_request.get('creator_id')
            self.project_id = parsed_request.get('project_id')

        self.status = States.ACTIVE

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for k, v in self.secret_store_metadata.items():
            v.delete(session)

        for k, v in self.secret_user_metadata.items():
            v.delete(session)

        for datum in self.encrypted_data:
            datum.delete(session)

        for secret_ref in self.container_secrets:
            secret_ref.delete(session)

        for secret_acl in self.secret_acls:
            secret_acl.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        if self.expiration:
            expiration = self.expiration.isoformat()
        else:
            expiration = self.expiration

        return {
            'secret_id': self.id,
            'name': self.name,
            'secret_type': self.secret_type,
            'expiration': expiration,
            'algorithm': self.algorithm,
            'bit_length': self.bit_length,
            'mode': self.mode,
            'creator_id': self.creator_id,
            "consumers": [
                {
                    "service": consumer.service,
                    "resource_type": consumer.resource_type,
                    "resource_id": consumer.resource_id,
                } for consumer in self.consumers if not consumer.deleted
            ],
        }


class SecretStoreMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Represents Secret Store metadatum for a single key-value pair."""

    __tablename__ = "secret_store_metadata"

    key = sa.Column(sa.String(255), nullable=False)
    value = sa.Column(sa.String(255), nullable=False)
    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=False)

    secret = orm.relationship(
        "Secret", back_populates="secret_store_metadata")

    def __init__(self, key=None, value=None, check_exc=True):
        super(SecretStoreMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for SecretStoreMetadatum entry.")

        if key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("key"))
        self.key = key

        if value is None and check_exc:
            raise exception.MissingArgumentError(msg.format("value"))
        self.value = value

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {
            'key': self.key,
            'value': self.value
        }


class SecretUserMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Represents Secret user metadatum for a single key-value pair."""

    __tablename__ = "secret_user_metadata"

    key = sa.Column(sa.String(255), nullable=False)
    value = sa.Column(sa.String(255), nullable=False)
    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=False)

    secret = orm.relationship(
        "Secret",
        back_populates="secret_user_metadata")

    __table_args__ = (
        sa.UniqueConstraint('secret_id', 'key', name='_secret_key_uc'),
    )

    def __init__(self, key=None, value=None, check_exc=True):
        super(SecretUserMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for SecretUserMetadatum entry.")

        if key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("key"))
        self.key = key

        if value is None and check_exc:
            raise exception.MissingArgumentError(msg.format("value"))
        self.value = value

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {
            'key': self.key,
            'value': self.value
        }


class EncryptedDatum(BASE, SoftDeleteMixIn, ModelBase):
    """Represents the encrypted data for a Secret."""

    __tablename__ = 'encrypted_data'

    content_type = sa.Column(sa.String(255))
    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=False)
    kek_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('kek_data.id'),
        index=True,
        nullable=False)
    # TODO(jwood) Why LargeBinary on Postgres (BYTEA) not work correctly?
    cypher_text = sa.Column(sa.Text)
    kek_meta_extended = sa.Column(sa.Text)

    # Eager load this relationship via 'lazy=False'.
    kek_meta_project = orm.relationship("KEKDatum", lazy=False)

    def __init__(self, secret=None, kek_datum=None, check_exc=True):
        """Creates encrypted datum from a secret and KEK metadata."""
        super(EncryptedDatum, self).__init__()

        if secret:
            self.secret_id = secret.id

        if kek_datum:
            self.kek_id = kek_datum.id
            self.kek_meta_project = kek_datum

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'content_type': self.content_type}


class KEKDatum(BASE, SoftDeleteMixIn, ModelBase):
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

    Note as well that each Project will have at most one 'active=True' KEKDatum
    instance at a time, representing the most recent KEK metadata instance
    to use for encryption processes performed on behalf of the Project.
    KEKDatum instances that are 'active=False' are associated to previously
    used encryption processes for the Project, that eventually should be
    rotated and deleted with the Project's active KEKDatum.
    """

    __tablename__ = 'kek_data'

    plugin_name = sa.Column(sa.String(255), nullable=False)
    kek_label = sa.Column(sa.String(255))
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='kek_data_project_fk'),
        index=True,
        nullable=False)
    active = sa.Column(sa.Boolean, nullable=False, default=True)
    bind_completed = sa.Column(sa.Boolean, nullable=False, default=False)
    algorithm = sa.Column(sa.String(255))
    bit_length = sa.Column(sa.Integer)
    mode = sa.Column(sa.String(255))
    plugin_meta = sa.Column(sa.Text)

    project = orm.relationship('Project', back_populates='keks')

    def __index__(self, check_exc=True):
        super(KEKDatum, self).__init__()

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'algorithm': self.algorithm}


class Order(BASE, SoftDeleteMixIn, ModelBase):
    """Represents an Order in the datastore.

    Orders are requests for Barbican to generate secrets,
    ranging from symmetric, asymmetric keys to automated
    requests to Certificate Authorities to generate SSL
    certificates.
    """

    __tablename__ = 'orders'

    type = sa.Column(sa.String(255), nullable=False, default='key')
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='orders_project_fk'),
        index=True,
        nullable=False)
    error_status_code = sa.Column(sa.String(16))
    error_reason = sa.Column(sa.String(ERROR_REASON_LENGTH))
    meta = sa.Column(JsonBlob(), nullable=True)
    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=True)
    container_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('containers.id'),
        index=True,
        nullable=True)
    sub_status = sa.Column(sa.String(SUB_STATUS_LENGTH), nullable=True)
    sub_status_message = sa.Column(
        sa.String(SUB_STATUS_MESSAGE_LENGTH),
        nullable=True)
    creator_id = sa.Column(sa.String(255))

    project = orm.relationship('Project', back_populates='orders')
    order_plugin_metadata = orm.relationship(
        "OrderPluginMetadatum",
        collection_class=col.attribute_mapped_collection('key'),
        back_populates="order",
        cascade="all, delete-orphan",
        cascade_backrefs=False)
    order_barbican_metadata = orm.relationship(
        "OrderBarbicanMetadatum",
        collection_class=col.attribute_mapped_collection('key'),
        back_populates="order",
        cascade="all, delete-orphan",
        cascade_backrefs=False)

    def __init__(self, parsed_request=None, check_exc=True):
        """Creates a Order entity from a dict."""
        super(Order, self).__init__()
        if parsed_request:
            self.type = parsed_request.get('type')
            self.meta = parsed_request.get('meta')
            self.status = States.ACTIVE
            self.sub_status = parsed_request.get('sub_status')
            self.sub_status_message = parsed_request.get(
                'sub_status_message')
            self.creator_id = parsed_request.get('creator_id')

    def set_error_reason_safely(self, error_reason_raw):
        """Ensure error reason does not raise database attribute exceptions."""
        self.error_reason = error_reason_raw[:ERROR_REASON_LENGTH]

    def set_sub_status_safely(self, sub_status_raw):
        """Ensure sub-status does not raise database attribute exceptions."""
        self.sub_status = sub_status_raw[:SUB_STATUS_LENGTH]

    def set_sub_status_message_safely(self, sub_status_message_raw):
        """Ensure status message doesn't raise database attrib. exceptions."""
        self.sub_status_message = sub_status_message_raw[
            :SUB_STATUS_MESSAGE_LENGTH
        ]

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for k, v in self.order_plugin_metadata.items():
            v.delete(session)
        for k, v in self.order_barbican_metadata.items():
            v.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        ret = {
            'type': self.type,
            'meta': self.meta,
            'order_id': self.id
        }
        if self.secret_id:
            ret['secret_id'] = self.secret_id
        if self.container_id:
            ret['container_id'] = self.container_id
        if self.error_status_code:
            ret['error_status_code'] = self.error_status_code
        if self.error_reason:
            ret['error_reason'] = self.error_reason
        if self.sub_status:
            ret['sub_status'] = self.sub_status
        if self.sub_status_message:
            ret['sub_status_message'] = self.sub_status_message
        if self.creator_id:
            ret['creator_id'] = self.creator_id
        return ret


class OrderPluginMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Represents Order plugin metadatum for a single key-value pair.

    This entity is used to store plugin-specific metadata on behalf of an
    Order instance.
    """

    __tablename__ = "order_plugin_metadata"

    order_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('orders.id'),
        index=True,
        nullable=False)
    key = sa.Column(sa.String(255), nullable=False)
    value = sa.Column(sa.String(255), nullable=False)

    order = orm.relationship("Order", back_populates="order_plugin_metadata")

    def __init__(self, key=None, value=None, check_exc=True):
        super(OrderPluginMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for OrderPluginMetadatum entry.")

        if key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("key"))
        self.key = key

        if value is None and check_exc:
            raise exception.MissingArgumentError(msg.format("value"))
        self.value = value

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'key': self.key,
                'value': self.value}


class OrderBarbicanMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Represents Order barbican metadatum for a single key-value pair.

    This entity is used to store barbican-specific metadata on behalf of an
    Order instance.  This is data that is stored by the server to help
    process the order through its life cycle, but which is not in the original
    request.
    """

    __tablename__ = "order_barbican_metadata"

    order_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('orders.id'),
        index=True,
        nullable=False)
    key = sa.Column(sa.String(255), nullable=False)
    value = sa.Column(sa.Text, nullable=False)

    order = orm.relationship("Order", back_populates="order_barbican_metadata")

    def __init__(self, key=None, value=None, check_exc=True):
        super(OrderBarbicanMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for OrderBarbicanMetadatum entry.")

        if key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("key"))
        self.key = key

        if value is None and check_exc:
            raise exception.MissingArgumentError(msg.format("value"))
        self.value = value

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'key': self.key,
                'value': self.value}


class OrderRetryTask(BASE, SoftDeleteMixIn, ModelBase):

    __tablename__ = "order_retry_tasks"
    __table_args__ = {"mysql_engine": "InnoDB"}
    __table_initialized__ = False

    id = sa.Column(
        sa.String(36),
        primary_key=True,
        default=utils.generate_uuid)
    order_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("orders.id"),
        index=True,
        nullable=False)
    retry_task = sa.Column(sa.Text, nullable=False)
    retry_at = sa.Column(sa.DateTime, default=None, nullable=False)
    retry_args = sa.Column(JsonBlob(), nullable=False)
    retry_kwargs = sa.Column(JsonBlob(), nullable=False)
    retry_count = sa.Column(sa.Integer, nullable=False, default=0)

    def __index__(self, check_exc):
        super(OrderRetryTask, self).__init__()


class Container(BASE, SoftDeleteMixIn, ModelBase):
    """Represents a Container for Secrets in the datastore.

    Containers store secret references. Containers are owned by Projects.
    Containers can be generic or have a predefined type. Predefined typed
    containers allow users to store structured key relationship
    inside Barbican.
    """

    __tablename__ = 'containers'

    name = sa.Column(sa.String(255))
    type = sa.Column(
        sa.Enum(
            'generic', 'rsa', 'dsa', 'certificate',
            name='container_types'))
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='containers_project_fk'),
        index=True,
        nullable=False)
    creator_id = sa.Column(sa.String(255))

    project = orm.relationship('Project', back_populates='containers')
    consumers = orm.relationship('ContainerConsumerMetadatum')
    container_acls = orm.relationship(
        'ContainerACL',
        back_populates='container',
        lazy=False)
    container_secrets = orm.relationship(
        "ContainerSecret",
        primaryjoin='and_(ContainerSecret.container_id==Container.id, ContainerSecret.deleted!=True)',  # noqa: E501
        back_populates='container',
        lazy=False,
    )

    def __init__(self, parsed_request=None, check_exc=True):
        """Creates a Container entity from a dict."""
        super(Container, self).__init__()

        if parsed_request:
            self.name = parsed_request.get('name')
            self.type = parsed_request.get('type')
            self.status = States.ACTIVE
            self.creator_id = parsed_request.get('creator_id')

            secret_refs = parsed_request.get('secret_refs')
            if secret_refs:
                for secret_ref in parsed_request.get('secret_refs'):
                    container_secret = ContainerSecret()
                    container_secret.name = secret_ref.get('name')
                    # TODO(hgedikli) move this into a common location
                    # TODO(hgedikli) validate provided url
                    # TODO(hgedikli) parse out secret_id with regex
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

        for container_acl in self.container_acls:
            session.delete(container_acl)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'container_id': self.id,
                'name': self.name,
                'type': self.type,
                'creator_id': self.creator_id,
                'secret_refs': [
                    {
                        'secret_id': container_secret.secret_id,
                        'name': container_secret.name
                        if hasattr(container_secret, 'name') else None
                    } for container_secret in self.container_secrets],
                'consumers': [
                    {
                        'name': consumer.name,
                        'URL': consumer.URL
                    } for consumer in self.consumers if not consumer.deleted
                ]}


class ContainerConsumerMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Stores Consumer Registrations for Containers in the datastore.

    Services can register interest in Containers. Services will provide a type
    and a URL for the object that is using the Container.
    """

    __tablename__ = 'container_consumer_metadata'

    container_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('containers.id'),
        index=True,
        nullable=False)
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id'),
        index=True,
        nullable=True)
    name = sa.Column(sa.String(36))
    URL = sa.Column(sa.String(255))
    data_hash = sa.Column(sa.CHAR(64))

    __table_args__ = (
        sa.UniqueConstraint('data_hash',
                            name='_consumer_hashed_container_name_url_uc'),
        sa.Index('values_index', 'container_id', 'name', 'URL')
    )

    def __init__(self, container_id=None, project_id=None,
                 parsed_request=None, check_exc=True):
        """Registers a Consumer to a Container."""
        super(ContainerConsumerMetadatum, self).__init__()

        # TODO(john-wood-w) This class should really be immutable due to the
        # data_hash attribute.
        if container_id and parsed_request:
            self.container_id = container_id
            self.project_id = project_id
            self.name = parsed_request.get('name')
            self.URL = parsed_request.get('URL')
            hash_text = ''.join((self.container_id, self.name, self.URL))
            self.data_hash = hashlib.sha256(hash_text.
                                            encode('utf-8')).hexdigest()
            self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'name': self.name,
                'URL': self.URL}


class TransportKey(BASE, SoftDeleteMixIn, ModelBase):
    """Transport Key model for wrapping secrets in transit

    Represents the transport key used for wrapping secrets in transit
    to/from clients when storing/retrieving secrets.
    """

    __tablename__ = 'transport_keys'

    plugin_name = sa.Column(sa.String(255), nullable=False)
    transport_key = sa.Column(sa.Text, nullable=False)

    def __init__(self, plugin_name=None, transport_key=None, check_exc=True):
        """Creates transport key entity."""
        super(TransportKey, self).__init__()

        msg = u._("Must supply non-None {0} argument for TransportKey entry.")

        if plugin_name is None and check_exc:
            raise exception.MissingArgumentError(msg.format("plugin_name"))

        self.plugin_name = plugin_name

        if transport_key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("transport_key"))

        self.transport_key = transport_key
        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'transport_key_id': self.id,
                'plugin_name': self.plugin_name}


class CertificateAuthority(BASE, ModelBase):
    """CertificateAuthority model to specify the CAs available to Barbican

    Represents the CAs available for certificate issuance to Barbican.
    """

    __tablename__ = 'certificate_authorities'

    plugin_name = sa.Column(sa.String(255), nullable=False)
    plugin_ca_id = sa.Column(sa.Text, nullable=False)
    expiration = sa.Column(sa.DateTime, default=None)
    creator_id = sa.Column(sa.String(255), nullable=True)
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='cas_project_fk'),
        nullable=True)

    ca_meta = orm.relationship(
        'CertificateAuthorityMetadatum',
        collection_class=col.attribute_mapped_collection('key'),
        back_populates='ca',
        cascade="all, delete-orphan",
        cascade_backrefs=False)
    project_cas = orm.relationship(
        'ProjectCertificateAuthority',
        back_populates='ca')
    preferred_ca = orm.relationship(
        'PreferredCertificateAuthority',
        back_populates='ca')

    def __init__(self, parsed_ca_in=None, check_exc=True):
        """Creates certificate authority entity."""
        super(CertificateAuthority, self).__init__()

        msg = u._("Must supply Non-None {0} argument "
                  "for CertificateAuthority entry.")

        parsed_ca = dict(parsed_ca_in)

        plugin_name = parsed_ca.pop('plugin_name', None)
        if plugin_name is None:
            raise exception.MissingArgumentError(msg.format("plugin_name"))
        self.plugin_name = plugin_name

        plugin_ca_id = parsed_ca.pop('plugin_ca_id', None)
        if plugin_ca_id is None:
            raise exception.MissingArgumentError(msg.format("plugin_ca_id"))
        self.plugin_ca_id = plugin_ca_id

        expiration = parsed_ca.pop('expiration', None)
        self.expiration = self._iso_to_datetime(expiration)

        creator_id = parsed_ca.pop('creator_id', None)
        if creator_id is not None:
            self.creator_id = creator_id

        project_id = parsed_ca.pop('project_id', None)
        if project_id is not None:
            self.project_id = project_id

        for key in parsed_ca:
            meta = CertificateAuthorityMetadatum(key, parsed_ca[key])
            self.ca_meta[key] = meta

        self.status = States.ACTIVE

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for k, v in self.ca_meta.items():
            v.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        if self.expiration:
            expiration = self.expiration.isoformat()
        else:
            expiration = None

        return {
            'ca_id': self.id,
            'plugin_name': self.plugin_name,
            'plugin_ca_id': self.plugin_ca_id,
            'expiration': expiration,
            'meta': [
                {
                    meta['key']: meta['value']
                } for key, meta in self.ca_meta.items()
            ]
        }


class CertificateAuthorityMetadatum(BASE, ModelBase):
    """Represents CA metadatum for a single key-value pair."""

    __tablename__ = "certificate_authority_metadata"

    key = sa.Column(sa.String(255), index=True, nullable=False)
    value = sa.Column(sa.Text, nullable=False)
    ca_id = sa.Column(
        sa.String(36), sa.ForeignKey('certificate_authorities.id'),
        index=True, nullable=False)

    ca = orm.relationship('CertificateAuthority', back_populates='ca_meta')

    __table_args__ = (
        sa.UniqueConstraint(
            'ca_id', 'key', name='_certificate_authority_metadatum_uc',
        ),
    )

    def __init__(self, key=None, value=None, check_exc=True):
        super(CertificateAuthorityMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for CertificateAuthorityMetadatum entry.")

        if key is None and check_exc:
            raise exception.MissingArgumentError(msg.format("key"))
        self.key = key

        if value is None and check_exc:
            raise exception.MissingArgumentError(msg.format("value"))
        self.value = value

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {
            'key': self.key,
            'value': self.value
        }


class ProjectCertificateAuthority(BASE, ModelBase):
    """Stores CAs available for a project.

    Admins can define a set of CAs that are available for use in a particular
    project.  There can be multiple entries for any given project.
    """

    __tablename__ = 'project_certificate_authorities'

    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id'),
        index=True,
        nullable=False)
    ca_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('certificate_authorities.id'),
        index=True,
        nullable=False)

    project = orm.relationship('Project', back_populates='cas')
    ca = orm.relationship("CertificateAuthority", back_populates='project_cas')

    __table_args__ = (
        sa.UniqueConstraint(
            'project_id', 'ca_id', name='_project_certificate_authority_uc',
        ),
    )

    def __init__(self, project_id=None, ca_id=None, check_exc=True):
        """Registers a Consumer to a Container."""
        super(ProjectCertificateAuthority, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for ProjectCertificateAuthority entry.")

        if project_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("project_id"))
        self.project_id = project_id

        if ca_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("ca_id"))
        self.ca_id = ca_id

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'project_id': self.project_id,
                'ca_id': self.ca_id}


class PreferredCertificateAuthority(BASE, ModelBase):
    """Stores preferred CAs for any project.

    Admins can define a set of CAs available for issuance requests for
    any project in the ProjectCertificateAuthority table..
    """

    __tablename__ = 'preferred_certificate_authorities'

    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id'),
        index=True,
        unique=True,
        nullable=False)
    ca_id = sa.Column(
        sa.String(36),
        sa.ForeignKey(
            'certificate_authorities.id',
            name='preferred_certificate_authorities_fk'),
        index=True,
        nullable=False)

    project = orm.relationship(
        'Project',
        back_populates='preferred_ca',
        uselist=False)
    ca = orm.relationship(
        'CertificateAuthority',
        back_populates='preferred_ca')

    def __init__(self, project_id=None, ca_id=None, check_exc=True):
        """Registers a Consumer to a Container."""
        super(PreferredCertificateAuthority, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for PreferredCertificateAuthority entry.")

        if project_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("project_id"))
        self.project_id = project_id

        if ca_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("ca_id"))
        self.ca_id = ca_id

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'project_id': self.project_id,
                'ca_id': self.ca_id}


class SecretACL(BASE, ModelBase):
    """Stores Access Control List (ACL) for a secret.

    Class to define whitelist of user ids who are allowed specific operation
    on a secret. List of user ids is defined via SecretACLUser via
    acl_users association.
    Creator_only flag helps in making a secret private for
    non-admin project users who may have access otherwise.

    SecretACL deletes are not soft-deletes.
    """

    __tablename__ = 'secret_acls'

    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secrets.id'),
        index=True,
        nullable=False)
    operation = sa.Column(sa.String(255), nullable=False)
    project_access = sa.Column(sa.Boolean, nullable=False, default=True)

    secret = orm.relationship(
        'Secret',
        back_populates='secret_acls',
        lazy=False)
    acl_users = orm.relationship(
        'SecretACLUser',
        back_populates='secret_acl',
        lazy=False,
        cascade="all, delete-orphan",
        cascade_backrefs=False)

    __table_args__ = (
        sa.UniqueConstraint(
            'secret_id', 'operation', name='_secret_acl_operation_uc',
        ),
    )

    def __init__(self, secret_id=None, operation=None, project_access=None,
                 user_ids=None, check_exc=True):
        """Creates secret ACL entity."""
        super(SecretACL, self).__init__()

        msg = u._("Must supply non-None {0} argument for SecretACL entry.")

        if secret_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("secret_id"))
        self.secret_id = secret_id

        if operation is None and check_exc:
            raise exception.MissingArgumentError(msg.format("operation"))
        self.operation = operation

        if project_access is not None:
            self.project_access = project_access
        self.status = States.ACTIVE
        if user_ids is not None and isinstance(user_ids, list):
            userids = set(user_ids)  # remove duplicate if any
            for user_id in userids:
                acl_user = SecretACLUser(self.id, user_id)
                self.acl_users.append(acl_user)

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for acl_user in self.acl_users:
            acl_user.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields.

        Adds non-deleted acl related users from relationship if there.
        """
        users = [acl_user.user_id for acl_user in self.acl_users
                 if not acl_user.deleted]
        fields = {'acl_id': self.id,
                  'secret_id': self.secret_id,
                  'operation': self.operation,
                  'project_access': self.project_access}
        if users:
            fields['users'] = users
        return fields


class ContainerACL(BASE, ModelBase):
    """Stores Access Control List (ACL) for a container.

    Class to define whitelist of user ids who are allowed specific operation
    on a container. List of user ids is defined in ContainerACLUser via
    acl_users association.
    Creator_only flag helps in making a container private for
    non-admin project users who may have access otherwise.

    ContainerACL deletes are not soft-deletes.
    """

    __tablename__ = 'container_acls'

    container_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('containers.id'),
        index=True,
        nullable=False)
    operation = sa.Column(sa.String(255), nullable=False)
    project_access = sa.Column(sa.Boolean, nullable=False, default=True)

    container = orm.relationship(
        'Container',
        back_populates='container_acls',
        lazy=False)
    acl_users = orm.relationship(
        'ContainerACLUser',
        back_populates='container_acl',
        cascade="all, delete-orphan",
        cascade_backrefs=False)

    __table_args__ = (
        sa.UniqueConstraint(
            'container_id', 'operation', name='_container_acl_operation_uc',
        ),
    )

    def __init__(self, container_id=None, operation=None, project_access=None,
                 user_ids=None, check_exc=True):
        """Creates container ACL entity."""
        super(ContainerACL, self).__init__()

        msg = u._("Must supply non-None {0} argument for ContainerACL entry.")

        if container_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("container_id"))
        self.container_id = container_id

        if operation is None and check_exc:
            raise exception.MissingArgumentError(msg.format("operation"))
        self.operation = operation

        if project_access is not None:
            self.project_access = project_access
        self.status = States.ACTIVE

        if user_ids is not None and isinstance(user_ids, list):
            userids = set(user_ids)  # remove duplicate if any
            for user_id in userids:
                acl_user = ContainerACLUser(self.id, user_id)
                self.acl_users.append(acl_user)

    def _do_delete_children(self, session):
        """Sub-class hook: delete children relationships."""
        for acl_user in self.acl_users:
            acl_user.delete(session)

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields.

        Adds non-deleted acl related users from relationship if there.
        """
        users = [acl_user.user_id for acl_user in self.acl_users
                 if not acl_user.deleted]
        fields = {'acl_id': self.id,
                  'container_id': self.container_id,
                  'operation': self.operation,
                  'project_access': self.project_access}
        if users:
            fields['users'] = users
        return fields


class SecretACLUser(BASE, ModelBase):
    """Stores user id for a secret ACL.

    This class provides way to store list of users associated with a
    specific ACL operation.

    SecretACLUser deletes are not soft-deletes.
    """

    __tablename__ = 'secret_acl_users'

    acl_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secret_acls.id'),
        index=True,
        nullable=False)
    user_id = sa.Column(sa.String(255), nullable=False)

    secret_acl = orm.relationship(
        'SecretACL',
        back_populates='acl_users',
        lazy=False)

    __table_args__ = (
        sa.UniqueConstraint('acl_id', 'user_id', name='_secret_acl_user_uc'),
    )

    def __init__(self, acl_id=None, user_id=None, check_exc=True):
        """Creates secret ACL user entity."""
        super(SecretACLUser, self).__init__()

        msg = u._("Must supply non-None {0} argument for SecretACLUser entry.")

        self.acl_id = acl_id
        if user_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("user_id"))
        self.user_id = user_id
        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'acl_id': self.acl_id,
                'user_id': self.user_id}


class ContainerACLUser(BASE, ModelBase):
    """Stores user id for a container ACL.

    This class provides way to store list of users associated with a
    specific ACL operation.

    ContainerACLUser deletes are not soft-deletes.
    """

    __tablename__ = 'container_acl_users'

    acl_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('container_acls.id'),
        index=True,
        nullable=False)
    user_id = sa.Column(sa.String(255), nullable=False)

    container_acl = orm.relationship(
        'ContainerACL',
        back_populates='acl_users',
        lazy=False)

    __table_args__ = (
        sa.UniqueConstraint(
            'acl_id', 'user_id', name='_container_acl_user_uc',
        ),
    )

    def __init__(self, acl_id=None, user_id=None, check_exc=True):
        """Creates container ACL user entity."""
        super(ContainerACLUser, self).__init__()

        msg = u._("Must supply non-None {0} argument for ContainerACLUser "
                  "entry.")

        self.acl_id = acl_id
        if user_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("user_id"))
        self.user_id = user_id
        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'acl_id': self.acl_id,
                'user_id': self.user_id}


class ProjectQuotas(BASE, ModelBase):
    """Stores Project Quotas.

    Class to define project specific resource quotas.

    Project quota deletes are not soft-deletes.
    """

    __tablename__ = 'project_quotas'

    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id', name='project_quotas_fk'),
        index=True,
        nullable=False)
    secrets = sa.Column(sa.Integer, nullable=True)
    orders = sa.Column(sa.Integer, nullable=True)
    containers = sa.Column(sa.Integer, nullable=True)
    consumers = sa.Column(sa.Integer, nullable=True)
    cas = sa.Column(sa.Integer, nullable=True)

    project = orm.relationship('Project', back_populates='project_quotas')

    def __init__(self, project_id=None, parsed_project_quotas=None,
                 check_exc=True):
        """Creates Project Quotas entity from a project and a dict.

        :param project_id: the internal id of the project with quotas
        :param parsed_project_quotas: a dict with the keys matching the
        resources for which quotas are to be set, and the values containing
        the quota value to be set for this project and that resource.
        :return: None
        """
        super(ProjectQuotas, self).__init__()

        msg = u._("Must supply non-None {0} argument for ProjectQuotas entry.")

        if project_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("project_id"))
        self.project_id = project_id

        if parsed_project_quotas is None:
            self.secrets = None
            self.orders = None
            self.containers = None
            self.consumers = None
            self.cas = None
        else:
            self.secrets = parsed_project_quotas.get('secrets')
            self.orders = parsed_project_quotas.get('orders')
            self.containers = parsed_project_quotas.get('containers')
            self.consumers = parsed_project_quotas.get('consumers')
            self.cas = parsed_project_quotas.get('cas')

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        ret = {
            'project_id': self.project_id,
        }
        if self.secrets:
            ret['secrets'] = self.secrets
        if self.orders:
            ret['orders'] = self.orders
        if self.containers:
            ret['containers'] = self.containers
        if self.consumers:
            ret['consumers'] = self.consumers
        if self.cas:
            ret['cas'] = self.cas
        return ret


class SecretStores(BASE, ModelBase):
    """List of secret stores defined via service configuration.

    This class provides a list of secret stores entities with their respective
    secret store plugin and crypto plugin names.

    SecretStores deletes are NOT soft-deletes.
    """

    __tablename__ = 'secret_stores'

    store_plugin = sa.Column(sa.String(255), nullable=False)
    crypto_plugin = sa.Column(sa.String(255), nullable=True)
    global_default = sa.Column(sa.Boolean, nullable=False, default=False)
    name = sa.Column(sa.String(255), nullable=False)

    project_store = orm.relationship(
        'ProjectSecretStore',
        back_populates='secret_store')

    __table_args__ = (
        sa.UniqueConstraint(
            'store_plugin', 'crypto_plugin',
            name='_secret_stores_plugin_names_uc'),
        sa.UniqueConstraint('name', name='_secret_stores_name_uc'),
    )

    def __init__(self, name=None, store_plugin=None, crypto_plugin=None,
                 global_default=None, check_exc=True):
        """Creates secret store entity."""
        super(SecretStores, self).__init__()

        msg = u._("Must supply non-Blank {0} argument for SecretStores entry.")

        if not name and check_exc:
            raise exception.MissingArgumentError(msg.format("name"))
        if not store_plugin and check_exc:
            raise exception.MissingArgumentError(msg.format("store_plugin"))

        self.store_plugin = store_plugin
        self.name = name
        self.crypto_plugin = crypto_plugin
        if global_default is not None:
            self.global_default = global_default

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'secret_store_id': self.id,
                'store_plugin': self.store_plugin,
                'crypto_plugin': self.crypto_plugin,
                'global_default': self.global_default,
                'name': self.name}


class ProjectSecretStore(BASE, ModelBase):
    """Stores secret store to be used for new project secrets.

    This class maintains secret store and project mapping so that new project
    secret entries uses it as plugin backend.

    ProjectSecretStores deletes are NOT soft-deletes.
    """

    __tablename__ = 'project_secret_store'

    secret_store_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('secret_stores.id'),
        index=True,
        nullable=False)
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('projects.id'),
        index=True,
        nullable=False)

    secret_store = orm.relationship(
        'SecretStores',
        back_populates='project_store')
    project = orm.relationship(
        'Project',
        back_populates='preferred_secret_store')

    __table_args__ = (
        sa.UniqueConstraint(
            'project_id', name='_project_secret_store_project_uc'),
    )

    def __init__(self, project_id=None, secret_store_id=None, check_exc=True):
        """Creates project secret store mapping entity."""
        super(ProjectSecretStore, self).__init__()

        msg = u._("Must supply non-None {0} argument for ProjectSecretStore "
                  " entry.")

        if not project_id and check_exc:
            raise exception.MissingArgumentError(msg.format("project_id"))
        self.project_id = project_id
        if not secret_store_id and check_exc:
            raise exception.MissingArgumentError(msg.format("secret_store_id"))
        self.secret_store_id = secret_store_id

        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {'secret_store_id': self.secret_store_id,
                'project_id': self.project_id}


class SecretConsumerMetadatum(BASE, SoftDeleteMixIn, ModelBase):
    """Stores Consumer Registrations for Secrets in the datastore.

    Services can register interest in Secrets. Services will provide a
    resource type and a resource id for the object that is using the Secret.
    """

    __tablename__ = "secret_consumer_metadata"

    secret_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("secrets.id"),
        index=True,
        nullable=False
    )
    project_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("projects.id"),
        index=True,
        nullable=True
    )
    service = sa.Column(sa.String(255), nullable=False)
    resource_type = sa.Column(sa.String(255), nullable=False)
    resource_id = sa.Column(sa.String(36), index=True, nullable=False)

    secret = orm.relationship("Secret", back_populates="consumers")

    __table_args__ = (
        sa.UniqueConstraint(
            "secret_id", "service", "resource_type", "resource_id",
            name="_secret_consumer_resource_uc"
        ),
    )

    def __init__(self, secret_id=None, project_id=None, service=None,
                 resource_type=None, resource_id=None, check_exc=True):
        """Registers a Consumer to a Secret."""
        super(SecretConsumerMetadatum, self).__init__()

        msg = u._("Must supply non-None {0} argument "
                  "for SecretConsumerMetadatum entry.")

        if secret_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("secret_id"))
        if project_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("project_id"))
        if service is None and check_exc:
            raise exception.MissingArgumentError(msg.format("service"))
        if resource_type is None and check_exc:
            raise exception.MissingArgumentError(msg.format("resource_type"))
        if resource_id is None and check_exc:
            raise exception.MissingArgumentError(msg.format("resource_id"))

        self.secret_id = secret_id
        self.project_id = project_id
        self.service = service
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.status = States.ACTIVE

    def _do_extra_dict_fields(self):
        """Sub-class hook method: return dict of fields."""
        return {
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
        }
