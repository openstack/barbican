# -*- coding: utf-8 -*-
"""
    Barbican API
    ~~~~~~~~~~~~

    The API for Barbican.

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
import uuid
import datetime
from dateutil.parser import parse
from flask import Blueprint, request, jsonify, Response, json
from models import Event, Tenant, Key, Agent, Policy
from database import db_session

api = Blueprint('api', __name__, url_prefix="/api")


@api.route('/')
def root():
    return jsonify(hello='World')

@api.route('/<int:tenant_id>/', methods=['GET', 'POST'])
def tenant(tenant_id):
    if request.method == 'POST':
        tenant = Tenant.query.filter_by(id=tenant_id).first()
        if tenant is None:
            tenant = Tenant(id=tenant_id)
            db_session.add(tenant)
            db_session.commit()
            return Response("Tenant created!", status=201)
        else:
            return Response("Tenant already exists!", status=200)
        return Response(status=201)
    else:
        tenant = Tenant.query.filter_by(id=tenant_id).first()
        if tenant is None:
            return Response("No tenant found!", status=404)
        else:
            return Response("Tenant found!", status=200)

@api.route('/<int:tenant_id>/policies/', methods=['GET', 'POST'])
def policies(tenant_id):
    if request.method == 'POST':
        for policy in request.json['policies']:
            keys = []
            for k in policy['keys']:
                key = Key(uuid=k['uuid'], filename=k['filename'], mime_type=k['mime_type'],
                          expiration=parse(k['expiration']), secret=k['secret'], owner=k['owner'],
                          group=k['group'], cacheable=k['cacheable'])
                keys.append(key)

            policy = Policy(uuid=policy['uuid'], name=policy['name'], tenant_id=tenant_id,
                            directory_name=policy['directory_name'],
                            max_key_accesses=policy['max_key_accesses'],
                            time_available_after_reboot=policy['time_available_after_reboot'])
            policy.keys.extend(keys)
            db_session.add(policy)
        db_session.commit()

        return Response(status=200)
    else:
        policy = Policy.query.filter_by(tenant_id=tenant_id).first()

        if policy is None:
            return Response('No policies defined for tenant', status=404)

        return jsonify(policy.as_dict())


@api.route('/<int:tenant_id>/agents/', methods=['GET', 'POST'])
def agents(tenant_id):
    if request.method == 'POST':
        tenant = Tenant.query.get(tenant_id)
        agent = Agent(tenant=tenant, uuid=request.json['uuid'])
        db_session.add(agent)
        db_session.commit()
        return jsonify(agent.as_dict())
    else:
        agents = Agent.query.filter_by(tenant_id=tenant_id)
        agents_dicts = map(Agent.as_dict, agents.all())
        return Response(json.dumps(agents_dicts, cls=DateTimeJsonEncoder), mimetype='application/json')



@api.route('/<int:tenant_id>/logs/', methods=['GET', 'POST'])
def logs(tenant_id):
    if request.method == 'POST':
        agent_id = uuid.UUID(request.json['agent_id'])
        received_on = parse(request.json['received_on'])
        key_id = uuid.UUID(request.json['key_id'])

        if request.json['severity'] in ['DEBUG', 'INFO', 'WARN', 'FATAL']:
            severity = request.json['severity']
        else:
            severity = 'UNKNOWN'

        # Load the key and tenant
        tenant = Tenant.query.get(tenant_id)
        key = Key.query.filter_by(uuid=str(key_id)).first()

        ev = Event(tenant_id=tenant_id, agent_id=str(agent_id), received_on=received_on,
                   severity=severity, message=request.json['message'], tenant=tenant, key=key)
        db_session.add(ev)
        db_session.commit()

        return Response(json.dumps(ev.as_dict(), cls=DateTimeJsonEncoder), mimetype='application/json')
    else:
        events = Event.query.filter_by(tenant_id=tenant_id).order_by(Event.received_on)
        events_dicts = map(Event.as_dict, events.all())
        return Response(json.dumps(events_dicts, cls=DateTimeJsonEncoder), mimetype='application/json')


class DateTimeJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        else:
            return super(DateTimeJsonEncoder, self).default(obj)