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
from flask import Blueprint, request, jsonify, Response, json, Markup
from models import Event, Tenant, Key, Agent, Policy, Tag
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
            return jsonify(tenant.as_dict()), 201
        else:
            return jsonify(tenant.as_dict())
        
     
    else:
        tenant = Tenant.query.filter_by(id=tenant_id).first()
        if tenant is None:
            return Response("No tenant found!", status=404)
        else:
            return jsonify(tenant.as_dict())

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
        agent = Agent(tenant=tenant, uuid=request.json['uuid'], hostname=request.json['hostname'],
                      os_version=request.json['os_version'], agent_version=request.json['agent_version'])
        tags = []
        for t in request.json['tags']:
            tag = Tag(name=t["name"], value=t["value"])
            tags.append(tag)
        
        agent.tags.extend(tags)
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

@api.route('/alllogs/', methods=['GET'])
def alllogs(timestamp=None):
    events = Event.query.order_by(Event.received_on)
    json_str = '''{
		 	"aaData":[ 
		'''
    for event in events.all():
         json_str += '''["%s","%s","%s","%s","%s","%s",	"%s"
                     ],'''  % (event.id,event.received_on, event.tenant_id, event.key_id, event.agent_id, event.severity, Markup.escape(event.message))
    json_str = json_str[:-1]
    json_str += ''']
		}'''
    return Response(json_str, mimetype='application/json')

@api.route('/allagents/', methods=['GET'])
def allagents(timestamp=None):
    agents = Agent.query.order_by(Agent.id)
    json_str = '''{
             "aaData":[ 
        '''
    for agent in agents.all():
         tags = Tag.query.filter(Tag.agent_id==agent.id).all()
         tag_json='{'
         for tag in tags:
             tag_json += "'%s':'%s'," % (tag.name, tag.value)
         tag_json = tag_json[:-1]
         tag_json += '}'
             
         if agent.paired == True:
             paired_checkbox = "<input type='checkbox' name='check%d' value='%d' checked>" % (agent.id, agent.id)
         else:
             paired_checkbox = "<input type='checkbox' name='check%d' value='%d'>" % (agent.id, agent.id)
         json_str += '''["%s","%s","%s","%s","%s","%s", "%s", "%s"
                     ],'''  % (agent.id,agent.uuid, agent.tenant_id, agent.hostname, agent.os_version, agent.agent_version, tag_json, paired_checkbox)
    json_str = json_str[:-1]
    json_str += ''']
        }'''
    return Response(json_str, mimetype='application/json')


class DateTimeJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        else:
            return super(DateTimeJsonEncoder, self).default(obj)

