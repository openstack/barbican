"""
Copyright 2015 Cisco Systems

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

from functionaltests.api.v1.models.base_models import BaseModel


class QuotaModel(BaseModel):

    def __init__(self, quotas=None):
        super(QuotaModel, self).__init__()
        self.quotas = quotas


class ProjectQuotaModel(BaseModel):

    def __init__(self, project_quotas=None, project_id=None):
        super(ProjectQuotaModel, self).__init__()
        self.project_quotas = project_quotas
        self.project_id = project_id


class ProjectQuotaRequestModel(BaseModel):

    def __init__(self, project_quotas=None):
        super(ProjectQuotaRequestModel, self).__init__()
        self.project_quotas = project_quotas
