# -*- coding: utf-8 -*-
"""
    Barbican
    ~~~~~~~~

    A proof of concept implementation of a key management server for
    use with the postern agent (https://github.com/cloudkeep/postern).

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
import os
from flask import Flask, render_template
from barbican_api import api
from database import db_session, init_db
from models import User


app = Flask(__name__)
app.register_blueprint(api)


@app.route("/")
def hello():
    return "Hello world!"


@app.route('/users')
def users_list():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()


if __name__ == '__main__':
    if not os.path.exists('/tmp/barbican.db'):
        init_db()
    app.run(debug=True)