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
Tasking related information that is shared/common across modules.
"""
from barbican import i18n as u


RETRY_MSEC_DEFAULT = 60 * 1000


class RetryTasks(object):
    """Defines tasks that can be retried/scheduled.

    RPC tasks invoked from the queue are handled via methods on
    barbican.queue.server.Tasks. These calls in turn delegate to the
    'process()' method of BaseTask sub-classes. These calls in turn delegate
    to business logic and plugins via modules in this barbican.tasks package.
    This class defines a common mechanism for the business logic and plugins
    to indicate what RPC tasks need to be retried in a way that the Tasks
    class can interpret as high level RPC tasks to enqueue later.

    In particular the following generic options are available:

    INVOKE_SAME_TASK - Invoke this same task later

    NO_ACTION_REQUIRED - To retry/scheduling actions are required


    The following task/context-specific actions are available:

    INVOKE_CERT_STATUS_CHECK_TASK - Check certificate status later

    """

    INVOKE_SAME_TASK = "Invoke Same Task Again Later"
    NO_ACTION_REQUIRED = "No Retry/Schedule Actions Are Needed"
    INVOKE_CERT_STATUS_CHECK_TASK = "Check Certificate Status Later"


class FollowOnProcessingStatusDTO(object):
    """Follow On Processing status data transfer object (DTO).

    An object of this type is optionally returned by the
    BaseTask.handle_processing() method defined below, and is used to guide
    follow on processing and to provide status feedback to clients.
    """
    def __init__(
        self,
        status=u._('Unknown'),
        status_message=u._('Unknown'),
        retry_task=RetryTasks.NO_ACTION_REQUIRED,
        retry_msec=RETRY_MSEC_DEFAULT
    ):
        """Creates a new FollowOnProcessingStatusDTO.

        :param status: Status for cert order
        :param status_message: Message to explain status type.
        :param retry_msec: Number of milliseconds to wait for retry
        :param retry_task: Task to retry, one of :class:`RetryTasks`
        """
        self.status = status
        self.status_message = status_message
        self.retry_task = retry_task

        if not retry_msec:
            self.retry_msec = 0
        else:
            self.retry_msec = max(int(retry_msec), 0)

    def is_follow_on_needed(self):
        if self.retry_task:
            return RetryTasks.NO_ACTION_REQUIRED != self.retry_task
        else:
            return False
