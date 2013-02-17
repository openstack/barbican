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

from flask import Flask
from barbican_api import api

app = Flask(__name__)
app.register_blueprint(api)


@app.route("/")
def hello():
    return "Hello world!"


if __name__ == '__main__':
    app.run()