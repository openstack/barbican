# Copyright 2026 Red Hat, Inc.
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

"""Migrate Barbican secrets onto another store.

Invoked as ``barbican-manage secret migrate``. Discovers candidate
secrets from the Barbican database, then calls
plugin.resources.rewrap_secret in-process. Never prints payloads.
"""

import argparse
import json
import sys

from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import exc as sa_exc
from sqlalchemy import or_
import sqlalchemy.orm as sa_orm

from barbican.common import exception as barbican_exc
from barbican.common import utils as barbican_utils
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin import resources as plugin


PROG = 'barbican-manage secret migrate'
DEFAULT_ERROR_FILE = 'barbican-manage-secret-migrate-errors.jsonl'


class Target(object):
    """One secret the command may migrate."""

    def __init__(self, secret_id, project_id, name='',
                 current_store_id=None, error=None, skip_reason=None):
        self.secret_id = secret_id
        self.project_id = project_id
        self.name = name or ''
        self.current_store_id = current_store_id
        self.error = error
        # Non-fatal skip (e.g. already on destination). Counted
        # separately from failures so retry/audit flows still see
        # every requested id.
        self.skip_reason = skip_reason


def secret_id_from_value(value):
    """Return a secret UUID from a UUID or secret href."""
    value = (value or '').strip().rstrip('/')
    if not value:
        raise ValueError('Empty secret id')
    secret_id = value.rsplit('/', 1)[-1]
    if not uuidutils.is_uuid_like(secret_id):
        raise ValueError('Not a UUID or secret href: %s' % value)
    return secret_id


def ids_from_file(path):
    """Load secret ids from a file (one UUID/href per line)."""
    with open(path, 'r', encoding='utf-8') as handle:
        return [
            secret_id_from_value(line)
            for raw in handle
            for line in [raw.strip()]
            if line and not line.startswith('#')
        ]


def initialize_runtime():
    """Open the Barbican DB using barbican.conf."""
    repos.setup_database_engine_and_factory()


def _require_store(store_id, label):
    store_repo = repos.get_secret_stores_repository()
    store = store_repo.get(entity_id=store_id, suppress_exception=True)
    if not store:
        raise RuntimeError(
            '%s secret store %s was not found in the '
            'secret_stores table' % (label, store_id))
    return store


def _require_project(external_id):
    project_repo = repos.get_project_repository()
    project = project_repo.find_by_external_project_id(
        external_id, suppress_exception=True)
    if not project:
        raise RuntimeError(
            'Project %s was not found in the Barbican database' %
            external_id)
    return project


def _query_secrets(session, project_id=None, secret_ids=None):
    query = session.query(models.Secret)
    query = query.filter_by(deleted=False)
    now = timeutils.utcnow()
    query = query.filter(or_(
        models.Secret.expiration.is_(None),
        models.Secret.expiration > now))
    if project_id:
        query = query.join(models.Secret.project)
        query = query.options(
            sa_orm.contains_eager(models.Secret.project))
        query = query.filter(models.Project.external_id == project_id)
    else:
        query = query.options(
            sa_orm.joinedload(models.Secret.project))
    if secret_ids:
        query = query.filter(models.Secret.id.in_(secret_ids))
    return query.order_by(models.Secret.created_at.asc()).all()


def discover_targets(args):
    """Return Target list from the Barbican database."""
    if not barbican_utils.is_multiple_backends_enabled():
        raise RuntimeError(
            'Multiple secret store backends are not enabled')

    _require_store(args.dest_store_id, 'Destination')
    if args.source_store_id:
        _require_store(args.source_store_id, 'Source')
    if args.project_id:
        _require_project(args.project_id)

    secret_ids = None
    if args.secret_id or args.secret_ids_file:
        values = list(args.secret_id or [])
        if args.secret_ids_file:
            values.extend(ids_from_file(args.secret_ids_file))
        secret_ids = list(dict.fromkeys(
            secret_id_from_value(v) for v in values))

    secrets = _query_secrets(
        repos.get_session(),
        project_id=args.project_id,
        secret_ids=secret_ids)

    found = {secret.id for secret in secrets}
    missing = [sid for sid in (secret_ids or []) if sid not in found]

    # Always record already-on-dest targets so summaries /
    # --secret-id retry audits account for every id. run() prints
    # per-id SKIP lines for dry-run and explicit id lists; bulk live
    # runs only count them.
    targets = []
    for sid in missing:
        targets.append(Target(
            secret_id=sid,
            project_id=args.project_id or '',
            error='Secret not found in Barbican database'))

    for secret in secrets:
        project = secret.project
        external_id = project.external_id if project else ''
        try:
            store = plugin.resolve_secret_store_for_secret(secret)
        except barbican_exc.SecretStoreNotResolved as exc:
            # Explicit ids: surface misconfig. Bulk scans omit (same
            # as no-payload) so a removed backend does not abort a
            # --source-store-id / --project-id drain of healthy rows.
            if secret_ids:
                targets.append(Target(
                    secret_id=secret.id,
                    project_id=external_id,
                    name=secret.name or '',
                    error=str(exc)))
            continue
        if store is None:
            if secret_ids:
                targets.append(Target(
                    secret_id=secret.id,
                    project_id=external_id,
                    name=secret.name or '',
                    error='Secret has no payload to migrate'))
            continue
        if (args.source_store_id and
                store.id != args.source_store_id):
            continue
        if store.id == args.dest_store_id:
            targets.append(Target(
                secret_id=secret.id,
                project_id=external_id,
                name=secret.name or '',
                current_store_id=store.id,
                skip_reason='already on destination store'))
            continue
        targets.append(Target(
            secret_id=secret.id,
            project_id=external_id,
            name=secret.name or '',
            current_store_id=store.id))
    return targets


def _rewrap_secret_by_id(secret_id, dest_store_id):
    """Load models from the DB and rewrap onto dest_store_id."""
    secret_repo = repos.get_secret_repository()
    secret = secret_repo.get_secret_by_id(
        secret_id, suppress_exception=True)
    if not secret:
        raise barbican_exc.NotFound(
            'Secret not found in Barbican database')
    store = _require_store(dest_store_id, 'Destination')
    plugin.rewrap_secret(secret, secret.project, store)
    # rewrap_secret only flushes; manage commands must commit
    # (HTTP requests commit via the API middleware instead).
    repos.commit()


def write_error_file(path, failures):
    with open(path, 'w', encoding='utf-8') as handle:
        for row in failures:
            handle.write(json.dumps(row, sort_keys=True) + '\n')


def add_migrate_arguments(parser):
    """Register migrate flags on an argparse parser."""
    parser.add_argument(
        '--dest-store-id',
        dest='dest_store_id',
        required=True,
        help='Destination secret store UUID')
    parser.add_argument(
        '--source-store-id',
        dest='source_store_id',
        help='Only secrets whose current backend is this store UUID')
    parser.add_argument(
        '--project-id',
        dest='project_id',
        help='Keystone project id whose secrets should be migrated')
    parser.add_argument(
        '--secret-id',
        action='append',
        default=[],
        dest='secret_id',
        help='Secret UUID or href (repeatable). Owning project is '
             'looked up in the database.')
    parser.add_argument(
        '--secret-ids-file',
        dest='secret_ids_file',
        help='File of secret UUIDs/hrefs, one per line')
    parser.add_argument(
        '--yes',
        action='store_true',
        dest='yes',
        help='Skip the confirmation prompt for bulk migrates '
             '(--project-id / --source-store-id)')
    parser.add_argument(
        '--dry-run',
        action='store_true',
        dest='dry_run',
        help='List secrets that would be migrated; do not rewrap')
    parser.add_argument(
        '--error-file',
        dest='error_file',
        help='JSONL file for failures (default: %s)' %
        DEFAULT_ERROR_FILE)


def validate_migrate_args(args, error=None):
    """Raise via error() when migrate flags are inconsistent."""
    def _error(message):
        if error is not None:
            error(message)
        raise ValueError(message)

    dest = getattr(args, 'dest_store_id', None)
    if not dest or not uuidutils.is_uuid_like(dest):
        _error('--dest-store-id must be a UUID')
    source = getattr(args, 'source_store_id', None)
    if source and not uuidutils.is_uuid_like(source):
        _error('--source-store-id must be a UUID')
    project_id = getattr(args, 'project_id', None)
    if project_id and not uuidutils.is_uuid_like(project_id):
        _error('--project-id must be a UUID')
    secret_id = getattr(args, 'secret_id', None) or []
    secret_ids_file = getattr(args, 'secret_ids_file', None)
    bulk = bool(project_id or source)
    explicit = bool(secret_id or secret_ids_file)
    if not bulk and not explicit:
        _error(
            'Provide --project-id, --source-store-id, --secret-id, '
            'or --secret-ids-file')
    if bulk and explicit:
        _error(
            '--secret-id / --secret-ids-file cannot be combined with '
            '--project-id or --source-store-id')
    if source and source == dest:
        _error(
            '--source-store-id and --dest-store-id must differ')


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            'Migrate Barbican secrets onto another secret store. '
            'Discovers secrets from the Barbican database, then '
            'calls plugin.resources.rewrap_secret in-process. '
            'Bulk migrates (--project-id / --source-store-id) '
            'prompt for confirmation unless --yes or --dry-run '
            'is set. Continues after per-secret failures. Never '
            'prints payloads.'))
    add_migrate_arguments(parser)
    args = parser.parse_args(argv)
    validate_migrate_args(args, error=parser.error)
    return args


def args_from_manage_kwargs(**kwargs):
    """Build a namespace from barbican-manage SecretCommands.migrate."""
    args = argparse.Namespace(
        dest_store_id=kwargs.get('dest_store_id'),
        source_store_id=kwargs.get('source_store_id'),
        project_id=kwargs.get('project_id'),
        secret_id=kwargs.get('secret_id') or [],
        secret_ids_file=kwargs.get('secret_ids_file'),
        yes=bool(kwargs.get('yes')),
        dry_run=bool(kwargs.get('dry_run')),
        error_file=kwargs.get('error_file'))
    validate_migrate_args(args)
    return args


def _label(target):
    if target.name:
        return '%s (%s)' % (target.secret_id, target.name)
    return target.secret_id


def _failure_row(target, dest_store_id, err):
    return {
        'secret_id': target.secret_id,
        'name': target.name or '',
        'project_id': target.project_id,
        'source_store_id': target.current_store_id,
        'target_store': dest_store_id,
        'error': err,
    }


def _is_bulk(args):
    return bool(args.project_id or args.source_store_id)


def confirm_bulk_migrate(args, count):
    """Prompt before a live bulk migrate unless --yes is set.

    Returns True when the migrate may proceed. Non-interactive
    bulk runs without --yes return False (caller exits 2).
    """
    if not _is_bulk(args) or args.dry_run or args.yes or count < 1:
        return True
    prompt = (
        'Migrate %s secret(s) to store %s? [y/N] ' % (
            count, args.dest_store_id))
    if not sys.stdin.isatty():
        sys.stderr.write(
            'ERROR: bulk migrate requires confirmation; '
            're-run with --yes (or use --dry-run)\n')
        return False
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        answer = sys.stdin.readline()
    except EOFError:
        answer = ''
    if answer.strip().lower() not in ('y', 'yes'):
        sys.stderr.write('Aborted.\n')
        return False
    return True


def run(args):
    try:
        targets = discover_targets(args)
    except (ValueError, RuntimeError, OSError,
            sa_exc.SQLAlchemyError) as exc:
        sys.stderr.write('ERROR: %s\n' % exc)
        return 2

    mode = 'dry-run' if args.dry_run else 'migrate'
    to_migrate = [
        t for t in targets
        if not t.error and not t.skip_reason]
    sys.stdout.write(
        '%s: %s %s secret(s) to store %s\n' % (
            PROG, mode, len(to_migrate), args.dest_store_id))
    if not targets:
        sys.stdout.write('Nothing to migrate.\n')
        return 0

    if not confirm_bulk_migrate(args, len(to_migrate)):
        return 2

    succeeded = 0
    skipped = 0
    failures = []
    list_skips = bool(
        args.dry_run or args.secret_id or args.secret_ids_file)

    for target in targets:
        label = _label(target)
        if target.error:
            failures.append(_failure_row(
                target, args.dest_store_id, target.error))
            sys.stderr.write('FAIL %s %s\n' % (label, target.error))
            continue
        if target.skip_reason:
            skipped += 1
            if list_skips:
                sys.stdout.write(
                    'SKIP %s %s\n' % (label, target.skip_reason))
            continue
        if args.dry_run:
            succeeded += 1
            extra = ''
            if target.project_id:
                extra = ' project=%s' % target.project_id
            sys.stdout.write(
                'OK would migrate %s%s\n' % (label, extra))
            continue

        try:
            _rewrap_secret_by_id(target.secret_id, args.dest_store_id)
        except (barbican_exc.BarbicanException, RuntimeError) as exc:
            # rewrap_secret flushes; clear this secret's session
            # state before continuing so a later peer commit cannot
            # persist a failed migrate.
            repos.rollback()
            err = '%s: %s' % (type(exc).__name__, exc)
            failures.append(_failure_row(
                target, args.dest_store_id, err))
            sys.stderr.write('FAIL %s %s\n' % (label, err))
            continue
        succeeded += 1
        sys.stdout.write('OK migrated %s\n' % label)

    sys.stdout.write(
        'Summary: ok=%s skipped=%s failed=%s total=%s\n' % (
            succeeded, skipped, len(failures), len(targets)))
    if skipped and not list_skips:
        sys.stdout.write(
            '(%s secret(s) already on destination; omitted '
            'per-id SKIP lines for bulk run)\n' % skipped)
    if failures:
        error_path = args.error_file or DEFAULT_ERROR_FILE
        write_error_file(error_path, failures)
        sys.stderr.write(
            'Wrote %s failure record(s) to %s\n' % (
                len(failures), error_path))
        # Dry-run is advisory: keep reporting discover problems in
        # the summary / error file, but do not fail the process.
        if args.dry_run:
            return 0
        return 1
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    return main_from_args(parse_args(argv))


def main_from_args(args):
    try:
        initialize_runtime()
    except (barbican_exc.BarbicanException,
            sa_exc.SQLAlchemyError,
            OSError,
            RuntimeError) as exc:
        sys.stderr.write('ERROR: failed to initialize Barbican '
                         'runtime: %s\n' % exc)
        return 2
    return run(args)


if __name__ == '__main__':
    sys.exit(main())
