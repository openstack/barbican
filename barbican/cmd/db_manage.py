#!/usr/bin/env python
# Copyright 2010-2015 OpenStack LLC.
# All Rights Reserved.
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

import argparse
import os
import sys

sys.path.insert(0, os.getcwd())

from barbican.common import config
from barbican.model.migration import commands
from oslo_log import log


class DatabaseManager(object):
    """Database Manager class.

    Builds and executes a CLI parser to manage the Barbican database
    This extends the Alembic commands.
    """

    def __init__(self, conf):
        self.conf = conf
        self.parser = self.get_main_parser()
        self.subparsers = self.parser.add_subparsers(
            title='subcommands',
            description='Action to perform')
        self.add_revision_args()
        self.add_upgrade_args()
        self.add_history_args()
        self.add_current_args()

    def get_main_parser(self):
        """Create top-level parser and arguments."""
        parser = argparse.ArgumentParser(description='Barbican DB manager.')
        parser.add_argument('--dburl', '-d', default=self.conf.sql_connection,
                            help='URL to the database.')

        return parser

    def add_revision_args(self):
        """Create 'revision' command parser and arguments."""
        create_parser = self.subparsers.add_parser('revision', help='Create a '
                                                   'new DB version file.')
        create_parser.add_argument('--message', '-m', default='DB change',
                                   help='the message for the DB change')
        create_parser.add_argument('--autogenerate',
                                   help='autogenerate from models',
                                   action='store_true')
        create_parser.set_defaults(func=self.revision)

    def add_upgrade_args(self):
        """Create 'upgrade' command parser and arguments."""
        create_parser = self.subparsers.add_parser('upgrade',
                                                   help='Upgrade to a '
                                                   'future version DB '
                                                   'version file')
        create_parser.add_argument('--version', '-v', default='head',
                                   help='the version to upgrade to, or else '
                                        'the latest/head if not specified.')
        create_parser.set_defaults(func=self.upgrade)

    def add_history_args(self):
        """Create 'history' command parser and arguments."""
        create_parser = self.subparsers.add_parser(
            'history',
            help='List changeset scripts in chronological order.')
        create_parser.add_argument('--verbose', '-V', action="store_true",
                                   help='Show full information about the '
                                        'revisions.')
        create_parser.set_defaults(func=self.history)

    def add_current_args(self):
        """Create 'current' command parser and arguments."""
        create_parser = self.subparsers.add_parser(
            'current',
            help='Display the current revision for a database.')
        create_parser.add_argument('--verbose', '-V', action="store_true",
                                   help='Show full information about the '
                                        'revision.')
        create_parser.set_defaults(func=self.current)

    def revision(self, args):
        """Process the 'revision' Alembic command."""
        commands.generate(autogenerate=args.autogenerate,
                          message=args.message,
                          sql_url=args.dburl)

    def upgrade(self, args):
        """Process the 'upgrade' Alembic command."""
        commands.upgrade(to_version=args.version, sql_url=args.dburl)

    def history(self, args):
        commands.history(args.verbose, sql_url=args.dburl)

    def current(self, args):
        commands.current(args.verbose, sql_url=args.dburl)

    def execute(self):
        """Parse the command line arguments."""
        args = self.parser.parse_args()

        # Perform other setup here...

        args.func(args)


def _exception_is_successfull_exit(thrown_exception):
    return (isinstance(thrown_exception, SystemExit) and
            (thrown_exception.code is None or thrown_exception.code == 0))


def main():
    # Import and configure logging.
    CONF = config.CONF
    log.setup(CONF, 'barbican')
    LOG = log.getLogger(__name__)
    LOG.debug("Performing database schema migration...")

    try:
        dm = DatabaseManager(CONF)
        dm.execute()
    except Exception as ex:
        if _exception_is_successfull_exit(ex):
            pass
        LOG.exception('Problem trying to execute Alembic commands')


if __name__ == '__main__':
    main()
