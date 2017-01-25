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


class OrderModel(base_models.BaseModel):

    def __init__(self, type=None, name=None, status=None, secret_ref=None,
                 expiration=None, updated=None, created=None, meta=None,
                 payload_content_type=None, order_ref=None, container_ref=None,
                 error_status_code=None, error_reason=None,
                 sub_status=None, sub_status_message=None, creator_id=None):
        super(OrderModel, self).__init__()
        self.type = type
        self.name = name
        self.status = status
        self.sub_status = sub_status
        self.sub_status_message = sub_status_message
        self.secret_ref = secret_ref
        self.expiration = expiration
        self.updated = updated
        self.created = created
        self.meta = meta
        self.payload_content_type = payload_content_type
        self.order_ref = order_ref
        self.container_ref = container_ref
        self.error_status_code = error_status_code
        self.error_reason = error_reason
        self.creator_id = creator_id
