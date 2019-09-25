"""
Copyright 2014-2015 Rackspace

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

from functionaltests.api.v1.models import base_models


class SecretModel(base_models.BaseModel):

    def __init__(self, name=None, expiration=None, algorithm=None,
                 secret_ref=None, bit_length=None, mode=None, secret_type=None,
                 payload_content_type=None, payload=None, content_types=None,
                 payload_content_encoding=None, status=None, updated=None,
                 created=None, creator_id=None, metadata=None, consumers=None):
        super(SecretModel, self).__init__()

        self.name = name
        self.expiration = expiration
        self.algorithm = algorithm
        self.bit_length = bit_length
        self.mode = mode
        self.secret_type = secret_type
        self.payload_content_type = payload_content_type
        self.payload = payload
        self.content_types = content_types
        self.payload_content_encoding = payload_content_encoding
        self.secret_ref = secret_ref
        self.status = status
        self.updated = updated
        self.created = created
        self.creator_id = creator_id
        self.metadata = metadata
        self.consumers = consumers
