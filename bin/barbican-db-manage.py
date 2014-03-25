#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os
import sys
import argparse

sys.path.insert(0, os.getcwd())

from barbican.model.migration import commands
from barbican.openstack.common import log


class DatabaseManager:
    """
    Builds and executes a CLI parser to manage the Barbican database,
    using Alembic commands.
    """

    def __init__(self):
        self.parser = self.get_main_parser()
        self.subparsers = self.parser.add_subparsers(title='subcommands',
                                                     description=
                                                     'Action to perform')
        self.add_revision_args()
        self.add_downgrade_args()
        self.add_upgrade_args()

    def get_main_parser(self):
        """Create top-level parser and arguments."""
        parser = argparse.ArgumentParser(description='Barbican DB manager.')
        parser.add_argument('--dburl', '-d', default=None,
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

    def add_downgrade_args(self):
        """Create 'downgrade' command parser and arguments."""
        create_parser = self.subparsers.add_parser('downgrade',
                                                   help='Downgrade to a '
                                                   'previous DB '
                                                   'version file.')
        create_parser.add_argument('--version', '-v', default='need version',
                                   help='the version to downgrade back to.')
        create_parser.set_defaults(func=self.downgrade)

    def revision(self, args):
        """Process the 'revision' Alembic command."""
        commands.generate(autogenerate=args.autogenerate,
                          message=args.message,
                          sql_url=args.dburl)

    def upgrade(self, args):
        """Process the 'upgrade' Alembic command."""
        commands.upgrade(to_version=args.version,
                         sql_url=args.dburl)

    def downgrade(self, args):
        """Process the 'downgrade' Alembic command."""
        commands.downgrade(to_version=args.version,
                           sql_url=args.dburl)

    def execute(self):
        """Parse the command line arguments."""
        args = self.parser.parse_args()

        # Perform other setup here...

        args.func(args)


def main():
    # Import and configure logging.
    log.setup('barbican-db-manage')
    LOG = log.getLogger(__name__)
    LOG.debug("Performing database schema migration...")

    dm = DatabaseManager()
    dm.execute()


if __name__ == '__main__':
    main()
