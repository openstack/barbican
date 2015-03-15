# Copyright (c) 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Common utilities for Barbican.
"""

import mimetypes
import time
import uuid

from oslo_config import cfg
from oslo_log import log
import pecan

from barbican import i18n as u


host_opts = [
    cfg.StrOpt('host_href', default='http://localhost:9311'),
]

CONF = cfg.CONF
CONF.register_opts(host_opts)


# Current API version
API_VERSION = 'v1'


def allow_all_content_types(f):
    # Pecan decorator to not limit content types for controller routes
    cfg = pecan.util._cfg(f)
    cfg.setdefault('content_types', {})
    cfg['content_types'].update((value, '')
                                for value in mimetypes.types_map.values())
    return f


def hostname_for_refs(resource=None):
    """Return the HATEOS-style return URI reference for this service."""
    ref = ['{base}/{version}'.format(base=CONF.host_href, version=API_VERSION)]
    if resource:
        ref.append('/' + resource)
    return ''.join(ref)


# Return a logger instance.
#   Note: Centralize access to the logger to avoid the dreaded
#   'ArgsAlreadyParsedError: arguments already parsed: cannot
#   register CLI option'
#   error.
def getLogger(name):
    return log.getLogger(name)


def get_accepted_encodings(req):
    """Returns a list of client acceptable encodings sorted by q value.

    For details see: http://tools.ietf.org/html/rfc2616#section-14.3

    :param req: request object
    :returns: list of client acceptable encodings sorted by q value.
    """
    header = req.get_header('Accept-Encoding')

    return get_accepted_encodings_direct(header)


def get_accepted_encodings_direct(content_encoding_header):
    """Returns a list of client acceptable encodings sorted by q value.

    For details see: http://tools.ietf.org/html/rfc2616#section-14.3

    :param req: request object
    :returns: list of client acceptable encodings sorted by q value.
    """
    if content_encoding_header is None:
        return None

    encodings = list()
    for enc in content_encoding_header.split(','):
        if ';' in enc:
            encoding, q = enc.split(';')
            try:
                q = q.split('=')[1]
                quality = float(q.strip())
            except ValueError:
                # can't convert quality to float
                return None
            if quality > 1.0 or quality < 0.0:
                # quality is outside valid range
                return None
            if quality > 0.0:
                encodings.append((encoding.strip(), quality))
        else:
            encodings.append((enc.strip(), 1))

    return [enc[0] for enc in sorted(encodings,
                                     cmp=lambda a, b: cmp(b[1], a[1]))]


def generate_fullname_for(instance):
    """Produce a fully qualified class name for the specified instance.

    :param instance: The instance to generate information from.
    :return: A string providing the package.module information for the
    instance.
    :raises: ValueError if the given instance is null
    """
    if not instance:
        raise ValueError(u._("Cannot generate a fullname for a null instance"))

    module = type(instance).__module__
    class_name = type(instance).__name__

    if module is None or module == "__builtin__":
        return class_name
    return "{module}.{class_name}".format(module=module, class_name=class_name)


class TimeKeeper(object):
    """TimeKeeper object

    Keeps track of elapsed times and then allows for dumping a summary to
    logs. This class can be used to profile a method as a fine grain level.
    """

    def __init__(self, name, logger=None):
        self.logger = logger or getLogger(__name__)
        self.name = name
        self.time_start = time.time()
        self.time_last = self.time_start
        self.elapsed = []

    def mark(self, note=None):
        """Mark a moment in time, with an optional note

        :param note: Optional note about what is occurring at this time
        """
        time_curr = time.time()
        self.elapsed.append((time_curr, time_curr - self.time_last, note))
        self.time_last = time_curr

    def dump(self):
        """Dump the elapsed time(s) to log."""
        self.logger.debug("Timing output for '{0}'".format(self.name))
        for timec, timed, note in self.elapsed:
            self.logger.debug("    time current/elapsed/notes:"
                              "{0:.3f}/{1:.0f}/{2}".format(timec,
                                                           timed * 1000.,
                                                           note))
        time_current = time.time()
        total_elapsed = time_current - self.time_start
        self.logger.debug("    Final time/elapsed:"
                          "{0:.3f}/{1:.0f}".format(time_current,
                                                   total_elapsed * 1000.))


def generate_uuid():
    return str(uuid.uuid4())
