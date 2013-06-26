import httplib


host = "localhost"
port = 9311
method = "GET"
timeout = 1000
body = None
path = "/"
headers = ""

expected_response = {"v1": "current", "build": "0.1.34dev"}


# Typically an authenticated user session will make a request for a key to
# barbican
# The restful request in all likelihood contain an auth token
# this test mimics such a request provided a token

# if pki tokens are used, the token is rather large
# uuid tokens are smaller and easier to test with
# assume there is a "demo" user with only member role

# curl -XPOST -d '{"auth":{"passwordCredentials":{"username": "demo", \
# "password": "secret"}, "tenantName": "demo"}}' \
# -H "Content-type: application/json" http://localhost:35357/v2.0/tokens
#
# pull out the token_id from above and use in ping_barbican
#

#TODO flesh this out
def get_demo_token(password):
    pass


def ping_barbican(token_id):
    headers = {'X_AUTH_TOKEN': token_id, 'X_IDENTITY_STATUS': 'Confirmed'}
    connection = httplib.HTTPConnection(host, port, timeout=timeout)
    connection.request(method, path, None, headers)
    response = connection.getresponse().read()
    connection.close()
    return response
