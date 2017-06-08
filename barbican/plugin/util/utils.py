# Copyright (c) 2015 Rackspace, Inc.
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
Utilities to support plugins and plugin managers.
"""
from barbican.common import utils

LOG = utils.getLogger(__name__)


def instantiate_plugins(extension_manager, invoke_args=(), invoke_kwargs={}):
    """Attempt to create each plugin managed by a stevedore manager.

    While we could have let the stevedore 'extension_manager' create our
    plugins by passing 'invoke_on_load=True' to its initializer, its logic
    handles and suppresses any root cause exceptions emanating from the
    plugins' initializers. This function allows those exceptions to be exposed.

    :param extension_manager: A :class:`NamedExtensionManager` instance that
        has already processed the configured plugins, but has not yet created
        instances of these plugins.
    :param invoke_args: Arguments to pass to the new plugin instance.
    :param invoke_kwargs: Keyword arguments to pass to the new plugin instance.
    """
    for ext in extension_manager.extensions:
        if not ext.obj:
            try:
                plugin_instance = ext.plugin(*invoke_args, **invoke_kwargs)
            except Exception:
                LOG.logger.disabled = False  # Ensure not suppressing logs.
                LOG.exception("Problem seen creating plugin: '%s'", ext.name)
            else:
                ext.obj = plugin_instance


def get_active_plugins(extension_manager):
    return [ext.obj for ext in extension_manager.extensions if ext.obj]
