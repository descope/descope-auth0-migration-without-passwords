from migration_utils import fetch_auth0_users, process_users, fetch_auth0_roles, process_roles, fetch_auth0_organizations, process_auth0_organizations
import sys
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def main():
    """
    Main function to process Auth0 users, roles, permissions, and organizations, creating and mapping them together within your Descope project.
    """
    # Fetch and Create Users
    auth0_users = fetch_auth0_users()
    process_users(auth0_users)

    # Fetch, create, and associate users with roles and permissions
    auth0_roles = fetch_auth0_roles()
    process_roles(auth0_roles)

    # Fetch, create, and associate users with Organizations
    auth0_organizations = fetch_auth0_organizations()
    process_auth0_organizations(auth0_organizations)

if __name__ == "__main__":
    import sys
    main()
