# -*- coding: utf-8 -*-
"""
    Barbican Models
    ~~~~~~~~~~~~~~~

    The models for Barbican.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
from uuid import uuid4
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import relationship, backref
from sqlalchemy.schema import ForeignKey
from database import Base


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    email = Column(String(120), unique=True)
    password = Column(String(50))

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __init__(self, name=None, email=None, password=None):
        self.name = name
        self.email = email
        self.password = password

    def __repr__(self):
        return '<User %r>' % self.name


class Tenant(Base):
    __tablename__ = 'tenants'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)

    def __init__(self, uuid=None, id=None):
        self.id = id
        if uuid is None:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid

    def __repr__(self):
        return '<Tenant %s>' % self.uuid
    
    def as_dict(self):
        json = {
            'id': self.id,
            'uuid': self.uuid
        }
        return json


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    filename = Column(String(128))
    mime_type = Column(String(128))
    expiration = Column(DateTime)
    secret = Column(Text)
    owner = Column(String(33))
    group = Column(String(33))
    cacheable = Column(Boolean)

    policy_id = Column(Integer, ForeignKey('policies.id'))
    policy = relationship("Policy", backref=backref('keys'))

    def __init__(self, uuid=None, filename=None, mime_type=None, expiration=None, secret=None,
                 owner=None, group=None, cacheable=None, policy_id=None):
        if uuid is None:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid

        self.filename = filename
        self.mime_type = mime_type
        self.expiration = expiration
        self.secret = secret
        self.owner = owner
        self.group = group
        self.cacheable = cacheable
        self.policy_id = policy_id

    def __repr__(self):
        return '<Key %s>' % self.uuid

    def as_dict(self):
        json = {
            'uuid': self.uuid,
            'filename': self.filename,
            'mime_type': self.mime_type,
            'expiration': self.expiration.isoformat(),
            'secret': self.secret,
            'owner': self.owner,
            'group': self.group,
            'cachecable': self.cacheable
        }
        return json


class Agent(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    hostname = Column(String(128))
    os_version = Column(String(128))
    agent_version = Column(String(33))
    paired = Column(Boolean)
    
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('agents', order_by=id))

    def __init__(self, tenant=None, uuid=None, hostname=None, os_version=None, agent_version=None, paired=None):
        self.tenant = tenant
        self.tenant_id = tenant.id
        if uuid is None:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid
        
        if paired is None:
            self.paired = False
        else:
            self.paired = paired
        self.hostname = hostname
        self.os_version = os_version
        self.agent_version = agent_version

    def __repr__(self):
        return '<Agent %s>' % self.uuid

    def as_dict(self):
        tags = map(Tag.as_dict, self.tags)
        agent = {
            'tenant_id': self.tenant_id,
            'uuid': self.uuid,
            'hostname': self.hostname,
            'os_version': self.os_version,
            'agent_version': self.agent_version,
            'paired': self.paired,
            'tags': tags
        }
        return agent


class Policy(Base):
    __tablename__ = 'policies'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    name = Column(String(100))
    directory_name = Column(String(254))
    max_key_accesses = Column(Integer)
    time_available_after_reboot = Column(Integer)

    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('policies', order_by=id))

    def __init__(self, uuid=None, name=None, directory_name=None, max_key_accesses=None,
                 time_available_after_reboot=None, tenant_id=None):
        if uuid is None:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid

        self.name = name
        self.directory_name = directory_name
        self.max_key_accesses = max_key_accesses
        self.time_available_after_reboot = time_available_after_reboot
        self.tenant_id = tenant_id

    def __repr__(self):
        return '<Policy %s >' % self.uuid

    def as_dict(self):
        keys = map(Key.as_dict, self.keys)

        json = {
            'uuid': self.uuid,
            'name': self.name,
            'directory_name': self.directory_name,
            'max_key_accesses': self.max_key_accesses,
            'time_available_after_reboot': self.time_available_after_reboot,
            'tenant_id': self.tenant_id,
            'keys': keys
        }
        return json


class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    agent_id = Column(String(36))
    received_on = Column(DateTime())
    severity = Column(String(10))
    message = Column(Text())

    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('events', order_by=id))

    key_id = Column(Integer, ForeignKey('keys.id'))
    key = relationship("Key", backref=backref('events', order_by=id))

    def __init__(self, tenant_id=None, agent_id=None, received_on=None, severity=None,
                 message=None, tenant=None, key=None):
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.received_on = received_on
        self.severity = severity
        self.message = message
        self.key = key
        self.tenant = tenant

    def __repr__(self):
        return '<Event %s [%s] - %s >' % (self.received_on, self.severity, self.message[:25])

    def as_dict(self):
        json = {
            'id': self.id,
            'agent_id': self.agent_id,
            'received_on': self.received_on.isoformat(),
            'severity': self.severity,
            'tenant_id': self.tenant_id,
            'key_id': self.key_id,
            'message': self.message
        }
        return json


class Tag(Base):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True)
    name = Column(String(128))
    value = Column(String(1024))

    agent_id = Column(Integer, ForeignKey('agents.id'))
    agent = relationship("Agent", backref=backref('tags'))

    def __init__(self, name=None, value=None):
        self.name = name 
        self.value = value 
 
    def __repr__(self):
        return '<Tag %s>' % self.id
    
    def as_dict(self):
        json = {
            'name': self.name,
            'value': self.value
        }
        return json
