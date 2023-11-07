from migration_utils import fetch_auth0_users, process_users, fetch_auth0_roles, process_roles, fetch_auth0_organizations, process_auth0_organizations
import sys
import logging
import argparse

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def main():
    """
    Main function to process Auth0 users, roles, permissions, and organizations, creating and mapping them together within your Descope project.
    """
    parser = argparse.ArgumentParser(description='This is a program to assist you in the migration of your users, roles, permissions, and organizations to Descope.')
    parser.add_argument('--dry-run', action='store_true', help='Enable dry run mode')
    args = parser.parse_args()
    dry_run = False

    if args.dry_run:
        dry_run=True

    # Fetch and Create Users
    auth0_users = fetch_auth0_users()
    process_users(auth0_users, dry_run)

    # Fetch, create, and associate users with roles and permissions
    auth0_roles = fetch_auth0_roles()
    process_roles(auth0_roles, dry_run)

    # Fetch, create, and associate users with Organizations
    auth0_organizations = fetch_auth0_organizations()
    process_auth0_organizations(auth0_organizations, dry_run)

if __name__ == "__main__":
    main()
