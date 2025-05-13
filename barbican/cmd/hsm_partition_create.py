"""
Command-line utility for creating HSM partition configurations
and mapping them to projects in the Barbican database.
"""

import argparse
import json
import sys
import uuid
import datetime

from oslo_utils import timeutils

from barbican.common import utils
from barbican.model import models
from barbican.model import repositories

DEFAULT_CREDS = {
    "library_path": "/usr/local/lib/softhsm/libsofthsm2.so",
    "password": "1234"
}

# Initialize logging and configuration
CONF = repositories.CONF
LOG = utils.getLogger(__name__)

# Set up command-line arguments
def main():
    parser = argparse.ArgumentParser(
        description='Create HSM partition configurations in Barbican.')

    parser.add_argument(
        '--external-project-id', '-p',
        help='External project ID',
        default='12345'
    )
    parser.add_argument(
        '--partition-label', '-l',
        help='Label for the HSM partition',
        default='hsm-partition-1'
    )
    parser.add_argument(
        '--token-label', '-t',
        help='Token label',
        default='testing'
    )
    parser.add_argument(
        '--slot-id', '-s',
        help='Slot ID for the HSM',
        type=int,
        default=175517174
    )
    parser.add_argument(
        '--library-path',
        help='Path to the HSM library',
        # I'm testing against softhsm2
        default='/usr/local/lib/softhsm/libsofthsm2.so'
    )
    parser.add_argument(
        '--password',
        help='Password/PIN for the HSM',
        default='1234'
    )
    parser.add_argument(
        '--partition-id',
        help='Override partition UUID (default: auto-generated)',
        default=None
    )
    parser.add_argument(
        '--mapping-id',
        help='Override mapping UUID (default: auto-generated)',
        default=None
    )
    parser.add_argument(
        '--debug',
        help='Enable debug output',
        action='store_true'
    )

    args = parser.parse_args()

    if args.debug:
        LOG.logger.setLevel('DEBUG')

    try:
        setup_database()
        create_hsm_partition(args)
        LOG.info("HSM partition configuration created successfully")
    except Exception as e:
        LOG.exception("Error creating HSM partition configuration: %s", e)
        return 1

    return 0

def setup_database():
    """Initialize database connection."""
    LOG.debug("Initializing database connection")
    repositories.setup_database_engine_and_factory()
    repositories.start()

def create_hsm_partition(args):
    """Create HSM partition configuration and map to project."""

    # Initialize session
    session = repositories.get_session()

    try:
        # Step 1: Check for existing external_id conflict
        project_query = session.query(models.Project).filter_by(
            external_id=args.external_project_id,
            deleted=False
        )

        project = project_query.first()
        if project:
            LOG.warning("Project (external_id: %s) already exists!", args.external_project_id)
        else:
            # Create project
            LOG.debug("Project doesn't exist, creating new one")
            project = models.Project()
            project.external_id = args.external_project_id
            project.status = models.States.ACTIVE
            project.deleted = False
            session.add(project)
            session.flush()
            LOG.debug("Created new project with id: %s", project.id)

        # Step: Create HSM partition config
        LOG.debug("Creating HSM partition config")
        hsm_partition_config = models.HSMPartitionConfig()

        # Always set the id explicitly for HSMPartitionConfig
        hsm_partition_config.id = args.partition_id or str(uuid.uuid4())
        hsm_partition_config.created_at = timeutils.utcnow()
        hsm_partition_config.updated_at = timeutils.utcnow()
        hsm_partition_config.project_id = project.id
        hsm_partition_config.partition_label = args.partition_label
        hsm_partition_config.token_label = args.token_label
        hsm_partition_config.slot_id = args.slot_id

        # Set credentials
        hsm_partition_config.credentials = {
            'library_path': args.library_path,
            'password': args.password
        }
        hsm_partition_config.status = models.States.ACTIVE
        hsm_partition_config.deleted = False

        session.add(hsm_partition_config)
        session.flush()  # This will assign an ID to the partition if needed
        LOG.debug("Created HSM partition config with id: %s", hsm_partition_config.id)

        # Step: Create project to HSM partition mapping
        LOG.debug("Creating project to HSM partition mapping")

        # Use the constructor correctly by providing required arguments
        mapping = models.ProjectHSMPartition(
            project_id=project.id,
            partition_id=hsm_partition_config.id,
            check_exc=False
        )
        # Set additional attributes
        mapping.id = args.mapping_id or str(uuid.uuid4())
        mapping.created_at = timeutils.utcnow()
        mapping.updated_at = timeutils.utcnow()
        mapping.status = models.States.ACTIVE
        mapping.deleted = False

        session.add(mapping)
        session.flush()  # This will assign an ID to the mapping if needed
        LOG.debug("Created mapping with id: %s", mapping.id)

        # Commit all changes
        session.commit()

        LOG.info("Successfully created HSM partition configuration:")
        LOG.info("  Project ID: %s (External ID: %s)", project.id, args.external_project_id)
        LOG.info("  Partition ID: %s (Label: %s)", hsm_partition_config.id, args.partition_label)
        LOG.info("  Mapping ID: %s", mapping.id)

    except Exception as e:
        LOG.exception("Error creating HSM partition configuration: %s", e)
        session.rollback()
        raise
    finally:
        session.close()

if __name__ == '__main__':
    sys.exit(main())
