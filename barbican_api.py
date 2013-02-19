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
import json
import uuid
from dateutil.parser import parse
from flask import Blueprint, request, jsonify
from models import Event
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

        if request.json['severity'] in ['DEBUG', 'INFO', 'WARN', 'FATAL']:
            severity = request.json['severity']
        else:
            severity = 'UNKNOWN'

        ev = Event(tenant_id=tenant_id, agent_id=str(agent_id), received_on=received_on,
                   severity=severity, message=request.json['message'])
        db_session.add(ev)
        db_session.commit()

        return jsonify(ev.as_dict())
    else:
        events = Event.query.filter_by(tenant_id=tenant_id).order_by(Event.received_on)
        return jsonify(json_list=events.all())


