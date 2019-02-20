"""
Copyright 2016 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from oslo_serialization import jsonutils as json

from functionaltests.api.v1.behaviors import base_behaviors


class SecretMetadataBehaviors(base_behaviors.BaseBehaviors):

    def create_or_update_metadata(self, secret_ref, data, extra_headers=None,
                                  use_auth=True, user_name=None, admin=None):

        meta_ref = '%s/metadata' % secret_ref
        data = json.dumps(data)

        resp = self.client.put(meta_ref, data=data,
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        metadata_ref = returned_data.get('metadata_ref')
        if metadata_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((metadata_ref, admin))
        return resp, metadata_ref

    def get_metadata(self, secret_ref, extra_headers=None, use_auth=True,
                     user_name=None, admin=None):

        meta_ref = '%s/metadata' % secret_ref
        resp = self.client.get(meta_ref, extra_headers=extra_headers,
                               user_name=user_name, use_auth=use_auth)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        metadata_ref = returned_data.get('metadata_ref')
        if metadata_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((metadata_ref, admin))
        return resp

    def create_metadatum(self, secret_ref, data, extra_headers=None,
                         use_auth=True, user_name=None, admin=None):
        meta_key_ref = '%s/%s' % (secret_ref, 'metadata')
        data = json.dumps(data)

        resp = self.client.post(meta_key_ref, data=data,
                                extra_headers=extra_headers, use_auth=use_auth,
                                user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        metadata_ref = returned_data.get('metadata_ref')
        if metadata_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((metadata_ref, admin))
        return resp, metadata_ref

    def update_metadatum(self, secret_ref, metadata_key, data,
                         extra_headers=None, use_auth=True, user_name=None,
                         admin=None):
        meta_key_ref = '%s/%s/%s' % (secret_ref, 'metadata', metadata_key)
        data = json.dumps(data)

        resp = self.client.put(meta_key_ref, data=data,
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        return resp

    def get_metadatum(self, secret_ref, metadata_key, extra_headers=None,
                      use_auth=True, user_name=None, admin=None):

        meta_key_ref = '%s/%s/%s' % (secret_ref, 'metadata', metadata_key)
        resp = self.client.get(meta_key_ref, extra_headers=extra_headers,
                               user_name=user_name, use_auth=use_auth)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        metadata_ref = returned_data.get('metadata_ref')
        if metadata_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((metadata_ref, admin))
        return resp

    def delete_metadatum(self, secret_ref, metadata_key, extra_headers=None,
                         use_auth=True, user_name=None, admin=None):

        meta_key_ref = '%s/%s/%s' % (secret_ref, 'metadata', metadata_key)
        resp = self.client.delete(meta_key_ref, extra_headers=extra_headers,
                                  user_name=user_name, use_auth=use_auth)

        return resp
