*****************************************
Certificate Authorities API - User Guide
*****************************************

Barbican is used as an interface to interact with Certificate Authorities (both
public and private) to issue, renew and revoke certificates.  In PKI parlance,
barbican acts as a Registration Authority for these CAs.

This interaction is done through certificate plugins, which in turn, can talk
to one of more CAs.  Details about the CA each plugin communicates with are
updated by the plugins.  This includes details like the CA name, description,
signing cert and PKCS#7 certificate chain.

Some certificate plugins also provide the ability to create subordinate CAs.
These are CAs which are generated on request by a client, which have signing
certificates which have been signed by another CA maintained by that plugin
(the parent CA).  More details will be provided below.

The CAs made available to barbican by the plugins are exposed to the client
through the /cas REST API, which is detailed in the
`Certificate Authorities API reference <http://docs.openstack.org/developer/barbican/api/reference/cas.html>`__.

This guide will provide some examples on how to use each of the supported
operations.  It assumes that you will be using a local running development
environment of barbican.  If you need assistance with getting set up, please
reference the
`development guide <http://docs.openstack.org/developer/barbican/setup/dev.html>`__.

.. _listing_the_cas:

Listing CAs
###########

To see the list of CA's that are currently configured, you can query the cas
resource:

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas

This should provide a response like the following:

.. code-block:: bash

    {"cas": ["http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581"], "total": 1}

.. _getting_ca_details:

Getting Details about a CA
##########################

More details on each CA can be obtained by querying the specific CA:

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581

The output shows the status of the CA and the plugin used to communicate with it:

.. code-block:: javascript

    {
        "status": "ACTIVE",
        "updated": "2015-05-09T05:55:37.745132",
        "created": "2015-05-09T05:55:37.745132",
        "plugin_name": "barbican.plugin.dogtag.DogtagCAPlugin",
        "meta": [
            {"name": "Dogtag CA"},
            {"description": "Certificate Authority - Dogtag CA"}
        ],
        "ca_id": "3a2a533d-ed4d-4c68-a418-2ee79f4c9581",
        "plugin_ca_id": "Dogtag CA",
        "expiration": "2015-05-10T05:55:37.740211"
    }

To get the signing certificate of the CA in PEM format (for importing into a
client), use the cacert sub-resource:

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/cacert

To get the PKCS#7 certificate chain (which contains the signing certificate and
all intermediate certificates), use the intermediates sub-resource.

.. code-block:: bash

    curl  -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/intermediates

.. _managing_project_cas:

Managing Project CAs
####################

It is possible to specify a set of CAs to be used for a particular project.
A project administrator can add or remove CAs from this list.  If this list
exists for a given project, then certificate orders will be routed only to those
CAs.  Any requests to other CAs (as specified by the ca_id in the order
metadata) will be rejected.

To add a CA to a particular project, a project administrator would do:

.. code-block:: bash

    curl  -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/add-to-project

To remove the CA from the set of project CAs, a project administrator would do:

.. code-block:: bash

    curl  -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/remove-from-project

The first CA added to the project will be designated as the preferred CA. This
is the CA to which requests that do not explicitly specify the ca_id will be
routed.  It is possible for project administrators to specify another project
CA as the preferred CA as follows:

.. code-block:: bash

    curl  -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/set-preferred

As a global administrator, it is possible to determine which projects a CA
belongs (ie. has been designated as a project CA) by querying the projects
sub-resource:

.. code-block:: bash

    curl  -X GET -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/projects

.. _setting_a_global_preferred_ca:

Setting a Global Preferred CA
#############################

It is possible for an administrator to set a global preferred CA.  This is the
CA to which certificate orders are routed if project CAs are not defined (see
previous section) and no ca_id is defined in the order.  If no global preferred
CA is defined, requests will be routed to the first configured certificate
plugin.

To set a global preferred CA plugin, do:

.. code-block:: bash

    curl  -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581/set-global-preferred

.. _creating_a_subca:

Creating a subordinate CA
#########################

As mentioned above, some certificate plugins (Dogtag and snake oil in
particular) allow projects to create new subordinate CAs on-the-fly.
These are CAs which have been signed by another CA (the "parent CA") exposed
by the same certificate plugin.

To determine if a particular CA can be used as a parent CA, get details about
the CA as exemplified in the :ref:`Getting Details<getting_ca_details>` section
above.  The attribute "can_create_subordinates" will be set to True if this CA
can be used as a subordinate CA.

A subordinate CA can then be created as follows:

.. code-block:: bash

    curl -X POST -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" -d '{
         "parent_ca_ref": "http://localhost:9311/cas/422e6ad3-24ae-45e3-b165-4e9487cd0ded",
         "subject_dn": "cn=Subordinate CA Signing Certificate, o=example.com",
         'name': "Subordinate CA"
    }' http://localhost:9311/v1/cas

The result of this JSON request will be a Certificate Authority reference,
which can be queried as above.

.. code-block:: bash

    {"order_ref": "http://localhost:9311/v1/cas/df1d1a0f-8454-46ca-9287-c57ced0418e7"}

.. _access_restrictions_on_sub_cas:

Access Restrictions on Subordinate CAs
######################################

Subordinate CAs are restricted to the project of the creator.  That is, the
creator's project_id is stored with the subordinate CA, and only members of the
creator's project are able to list, get details for or submit certificate
orders to a given subordinate CA.

Subordinate CAs can be distinguished from regular CAs by the presence of the
project_id and user_id in the CA details.

Subordinate CAs may be deleted by the user or a project administrator as
follows:

.. code-block:: bash

    curl  -X DEL -H "content-type:application/json" -H "X-Auth-Token: $TOKEN" \
        http://localhost:9311/v1/cas/3a2a533d-ed4d-4c68-a418-2ee79f4c9581
