#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
from barbican.common import utils


def convert_resource_id_to_href(resource_slug, resource_id):
    """Convert the resource ID to a HATEOAS-style href with resource slug."""
    if resource_id:
        resource = '{slug}/{id}'.format(slug=resource_slug, id=resource_id)
    else:
        resource = '{slug}/????'.format(slug=resource_slug)
    return utils.hostname_for_refs(resource=resource)


def convert_secret_to_href(secret_id):
    """Convert the secret IDs to a HATEOAS-style href."""
    return convert_resource_id_to_href('secrets', secret_id)


def convert_order_to_href(order_id):
    """Convert the order IDs to a HATEOAS-style href."""
    return convert_resource_id_to_href('orders', order_id)


def convert_container_to_href(container_id):
    """Convert the container IDs to a HATEOAS-style href."""
    return convert_resource_id_to_href('containers', container_id)


def convert_transport_key_to_href(transport_key_id):
    """Convert the transport key IDs to a HATEOAS-style href."""
    return convert_resource_id_to_href('transport_keys', transport_key_id)


def convert_consumer_to_href(consumer_id):
    """Convert the consumer ID to a HATEOAS-style href."""
    return convert_resource_id_to_href('consumers', consumer_id) + '/consumers'


def convert_user_meta_to_href(secret_id):
    """Convert the consumer ID to a HATEOAS-style href."""
    return convert_resource_id_to_href('secrets', secret_id) + '/metadata'


def convert_certificate_authority_to_href(ca_id):
    """Convert the ca ID to a HATEOAS-style href."""
    return convert_resource_id_to_href('cas', ca_id)


def convert_secret_stores_to_href(secret_store_id):
    """Convert the secret-store ID to a HATEOAS-style href."""
    return convert_resource_id_to_href('secret-stores', secret_store_id)


# TODO(hgedikli) handle list of fields in here
def convert_to_hrefs(fields):
    """Convert id's within a fields dict to HATEOAS-style hrefs."""
    if 'secret_id' in fields:
        fields['secret_ref'] = convert_secret_to_href(fields['secret_id'])
        del fields['secret_id']

    if 'order_id' in fields:
        fields['order_ref'] = convert_order_to_href(fields['order_id'])
        del fields['order_id']

    if 'container_id' in fields:
        fields['container_ref'] = convert_container_to_href(
            fields['container_id'])
        del fields['container_id']

    if 'transport_key_id' in fields:
        fields['transport_key_ref'] = convert_transport_key_to_href(
            fields['transport_key_id'])
        del fields['transport_key_id']

    return fields


def convert_list_to_href(resources_name, offset, limit):
    """Supports pretty output of paged-list hrefs.

    Convert the offset/limit info to a HATEOAS-style href
    suitable for use in a list navigation paging interface.
    """
    resource = '{0}?limit={1}&offset={2}'.format(resources_name, limit,
                                                 offset)
    return utils.hostname_for_refs(resource=resource)


def previous_href(resources_name, offset, limit):
    """Supports pretty output of previous-page hrefs.

    Create a HATEOAS-style 'previous' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = max(0, offset - limit)
    return convert_list_to_href(resources_name, offset, limit)


def next_href(resources_name, offset, limit):
    """Supports pretty output of next-page hrefs.

    Create a HATEOAS-style 'next' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = offset + limit
    return convert_list_to_href(resources_name, offset, limit)


def add_nav_hrefs(resources_name, offset, limit,
                  total_elements, data):
    """Adds next and/or previous hrefs to paged list responses.

    :param resources_name: Name of api resource
    :param offset: Element number (ie. index) where current page starts
    :param limit: Max amount of elements listed on current page
    :param total_elements: Total number of elements
    :returns: augmented dictionary with next and/or previous hrefs
    """
    if offset > 0:
        data.update({'previous': previous_href(resources_name,
                                               offset,
                                               limit)})
    if total_elements > (offset + limit):
        data.update({'next': next_href(resources_name,
                                       offset,
                                       limit)})
    return data


def get_container_id_from_ref(container_ref):
    """Parse a container reference and return the container ID

    TODO(Dave) Add some extra checking for valid prefix

    The container ID is the right-most element of the URL
    :param container_ref: HTTP reference of container
    :return: a string containing the ID of the container
    """
    container_id = container_ref.rsplit('/', 1)[1]
    return container_id


def get_secret_id_from_ref(secret_ref):
    """Parse a secret reference and return the secret ID

    :param secret_ref: HTTP reference of secret
    :return: a string containing the ID of the secret
    """
    secret_id = secret_ref.rsplit('/', 1)[1]
    return secret_id


def get_secrets_id_from_refs(secret_refs):
    """Parse a secret reference and return the list of secret ID

    :param secret_refs: a list of HTTP reference of secret
    :return: a string containing the ID of the secret
    """
    if secret_refs is None:
        return None
    secret_ids = []
    for secret_ref in secret_refs:
        secret_id = secret_ref.get('secret_ref')
        if secret_id.endswith('/'):
            secret_id = secret_id.rsplit('/', 2)[1]
        elif '/' in secret_id:
            secret_id = secret_id.rsplit('/', 1)[1]
        else:
            secret_id = secret_id
        secret_ids.append(secret_id)
    return secret_ids


def get_ca_id_from_ref(ca_ref):
    """Parse a ca_ref and return the CA ID

    :param ca_ref: HHTO reference of the CA
    :return: a string containing the ID of the CA
    """
    ca_id = ca_ref.rsplit('/', 1)[1]
    return ca_id
