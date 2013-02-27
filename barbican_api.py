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
from models import Event, Tenant, Key
from database import db_session

api = Blueprint('api', __name__, url_prefix="/api")


@api.route('/')
def root():
    return jsonify(hello='World')


@api.route('/<int:tenant_id>/logs/', methods=['GET', 'POST'])
def log(tenant_id):
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