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


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    filename = Column(String(128))
    mime_type = Column(String(128))
    expires = Column(DateTime)
    secret = Column(Text)

    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('keys', order_by=id))

    def __init__(self, uuid=None):
        if uuid is None:
            self.uuid = str(uuid4())

    def __repr__(self):
        return '<Key %s>' % self.uuid


class Agent(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)

    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('agents', order_by=id))

    def __init__(self, tenant=None, uuid=None):
        self.tenant = tenant
        if uuid is None:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid

    def __repr__(self):
        return '<Agent %s>' % self.uuid

    def as_dict(self):
        agent = {
            'tenant_id': self.tenant_id,
            'uuid': self.uuid
        }
        return agent


class Policy(Base):
    __tablename__ = 'policies'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)

    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    tenant = relationship("Tenant", backref=backref('policies', order_by=id))

    def __init__(self, uuid=None):
        if uuid is None:
            self.uuid = str(uuid4())

    def __repr__(self):
        return '<Policy %s >' % self.uuid


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
