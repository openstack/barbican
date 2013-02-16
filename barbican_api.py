# -*- coding: utf-8 -*-
"""
    Barbican API
    ~~~~~~

    The API for Barbican.

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
import json
from flask import Blueprint

api = Blueprint('api', __name__, url_prefix="/api")


@api.route('/')
def root():
    return json.dumps({'hello': 'world'})