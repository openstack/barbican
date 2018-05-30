# Copyright 2018 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from webob import acceptparse


if hasattr(acceptparse, 'create_accept_header'):
    # WebOb >= 1.8.0
    NoHeaderType = getattr(acceptparse, 'AcceptNoHeader')
    ValidHeaderType = getattr(acceptparse, 'AcceptValidHeader')
    create_accept_header = getattr(acceptparse, 'create_accept_header')
else:
    # WebOb < 1.8.0
    NoHeaderType = getattr(acceptparse, 'MIMENilAccept')
    ValidHeaderType = getattr(acceptparse, 'MIMEAccept')

    def create_accept_header(header_value):
        if not header_value:
            return NoHeaderType()
        else:
            return ValidHeaderType(header_value)
