=============
Microversions
=============

API v1.0 supports microversions: small, documented changes to the API. A user
can use microversions to discover the latest API microversion supported in
their cloud. A cloud that is upgraded to support newer microversions will
still support all older microversions to maintain the backward compatibility
for those users, who depend on older microversions. Users can also discover
new features easily with microversions, so that they can benefit from all the
advantages and improvements of the current cloud.

There are multiple cases which you can resolve with microversions:

- **Older clients with new cloud**

Before using an old client to talk to a newer cloud, the old client can check
the minimum version of microversions to verify whether the cloud is compatible
with the old API. This prevents the old client from breaking with backwards
incompatible API changes.

Currently the minimum version of microversions is `1.0`, which is a
microversion compatible with the legacy v1 API. That means the legacy v1 API
user doesn't need to worry that their older client software will be broken
when their cloud is upgraded with new versions. The cloud operator doesn't
need to worry that upgrading their cloud to newer versions will break any
user with older clients that don't expect these changes.

- **User discovery of available features between clouds**

The new features can be discovered by microversions. The user client should
first check the microversions supported by the server. New features are only
enabled when clouds support it. In this way, the user client can work with
clouds that have deployed different microversions simultaneously.

Version Discovery
=================

The Version API will return the minimum and maximum microversions. These
values are used by the client to discover the API's supported microversion(s).

Requests to '/' will get version info for all endpoints. A response would look
as follows::

  {
    "versions": [
        {
            "id": "v1.0",
            "links": [
                {
                    "href": "http://openstack.example.com/v1/",
                    "rel": "self"
                }
            ],
            "max_version": "1.1",
            "min_version": "1.0",
            "updated": "2021-02-10T00:00:00Z"
        }
    ]
  }

"max_version" is the maximum microversion, "min_version" is the minimum
microversion. The client should specify a microversion between
(and including) the minimum and maximum microversion to access the endpoint.

Client Interaction
==================

A client specifies the microversion of the API they want by using the following HTTP header::

  OpenStack-API-Version: key-manager 1.1

.. note:: For more detail on the syntax see the `Microversion Specification
   <http://specs.openstack.org/openstack/api-wg/guidelines/microversion_specification.html>`_.

This acts conceptually like the "Accept" header. Semantically this means:

* If `OpenStack-API-Version` (specifying `key-manager`) is not provided, act as
  if the minimum supported microversion was specified.

* If `OpenStack-API-Version` is provided, respond with the API at
  that microversion. If that's outside of the range
  of microversions supported, return 406 Not Acceptable.

* `OpenStack-API-Version` has a value of ``latest`` (special keyword),
  act as if maximum was specified.

.. warning:: The ``latest`` value is mostly meant for integration testing and
  would be dangerous to rely on in client code since microversions are not
  following semver and therefore backward compatibility is not guaranteed.
  Clients should always require a specific microversion but limit what is
  acceptable to the microversion range that it understands at the time.

This means that out of the box, an old client without any knowledge of
microversions can work with an OpenStack installation with microversions
support.

From microversion `1.1` two additional headers are added to the
response::

    OpenStack-API-Version: key-manager microversion_number
    Vary: OpenStack-API-Version
