import json
import os
import requests
from dotenv import load_dotenv
import logging
import time
import descope

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

"""Load and read environment variables from .env file"""
load_dotenv()
AUTH0_TOKEN = os.getenv("AUTH0_TOKEN")
AUTH0_TENANT_ID = os.getenv("AUTH0_TENANT_ID")
DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID")
DESCOPE_MANAGEMENT_KEY = os.getenv("DESCOPE_MANAGEMENT_KEY")

def api_request_with_retry(action, url, headers, data=None, max_retries=4):
    """
    Handles API requests with additional retry

    Args:
    - action (string): get or post
    - url (string): The URL of the path for the api request
    - data (json): Optional and used only for post, but the payload to post
    - max_retries (int): The max number of retries
    Returns:
    - API Response
    - Or None
    """
    retries = 0
    while retries < max_retries:
        if action == "get":
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, data=data)
        if response.status_code != 429:
            return response
        retries += 1
        wait_time = 5 ** retries
        logging.info(f"Rate limit reached. Retrying in {wait_time} seconds...")
        time.sleep(wait_time)
    logging.error("Max retries reached. Giving up.")
    return None

### Begin Auth0 Actions

def fetch_auth0_users():
    """
    Fetch and parse Auth0 users from the provided endpoint.

    Returns:
    - all_users (Dict): A list of parsed Auth0 users if successful, empty list otherwise.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_users = []
    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/users?page={page}&per_page={per_page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 users. Status code: {response.status_code}"
            )
            return all_users
        users = response.json()
        if not users:
            break
        all_users.extend(users)
        page += 1
    return all_users

def fetch_auth0_roles():
    """
    Fetch and parse Auth0 roles from the provided endpoint.

    Returns:
    - all_roles (Dict): A list of parsed Auth0 roles if successful, empty list otherwise.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_roles = []
    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/roles?page={page}&per_page={per_page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 roles. Status code: {response.status_code}"
            )
            return all_roles
        roles = response.json()
        if not roles:
            break
        all_roles.extend(roles)
        page += 1
    return all_roles

def get_users_in_role(role):
    """
    Get and parse Auth0 users associated with the provided role.

    Returns:
    - role (string): The role ID to get the associated members
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_users = []

    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/roles/{role}/users?page={page}&per_page={per_page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 users in roles. Status code: {response.status_code}"
            )
            return all_users
        users = response.json()
        if not users:
            break
        all_users.extend(users)
        page += 1
    return all_users

def get_permissions_for_role(role):
    """
    Get and parse Auth0 permissions for a role

    Args:
    - role (string): The id of the role to query for permissions
    Returns:
    - all_permissions (string): Dictionary of all permissions associated to the role.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_permissions = []

    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/roles/{role}/permissions?per_page={per_page}&page={page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 permissions in roles. Status code: {response.status_code}"
            )
            return all_permissions
        permissions = response.json()
        if not permissions:
            break
        all_permissions.extend(permissions)
        page += 1
    return all_permissions

def fetch_auth0_organizations():
    """
    Fetch and parse Auth0 organization members from the provided endpoint.

    Returns:
    - all_organizations (string): Dictionary of all organizations within the Auth0 tenant.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_organizations = []

    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/organizations?per_page={per_page}&page={page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 organizations. Status code: {response.status_code}"
            )
            return all_organizations
        organizations = response.json()
        if not organizations:
            break
        all_organizations.extend(organizations)
        page += 1
    return all_organizations

def fetch_auth0_organization_members(organization):
    """
    Fetch and parse Auth0 organization members from the provided endpoint.

    Args:
    - organization (string): Auth0 organization ID to fetch the members
    Returns:
    - all_members (dict): Dictionary of all members within the organization.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_members = []

    while True:
        response = api_request_with_retry("get",
            f"https://{AUTH0_TENANT_ID}.us.auth0.com/api/v2/organizations/{organization}/members?per_page={per_page}&page={page}",
            headers=headers
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 organization members. Status code: {response.status_code}"
            )
            return all_members
        members = response.json()
        if not members:
            break
        all_members.extend(members)
        page += 1
    return all_members

### Emd Auth0 Actions

### Begin Descope Actions

def create_descope_role_and_permissions(role, permissions):
    """
    Create a Descope role and it's associated permissions based on matched Auth0.

    Args:
    - role (dict): A dictionary containing role details from the Auth0.
    - permissions (dict): A dictionary containing permissions details from the Auth0.
    """
    permissionNames = []
    for permission in permissions:
        permissionNames.append(permission["permission_name"])
        payload_data = {
            "name": permission["permission_name"],
            "description": permission["description"]
        }
        payload = json.dumps(payload_data)
        url = "https://api.descope.com/v1/mgmt/permission/create"
        headers = {
            "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
            "Content-Type": "application/json",
        }
        response = api_request_with_retry("post", url, headers=headers, data=payload)
        if response.status_code != 200:
            logging.error(f"Unable to create permission.  Status code: {response.status_code}")
        else:
            logging.info("Permission successfully created")
            logging.info(response.text)
        
    payload_data = {
        "name": role["name"],
        "description": role["description"],
        "permissionNames": permissionNames
    }
    payload = json.dumps(payload_data)
    url = "https://api.descope.com/v1/mgmt/role/create"
    headers = {
        "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
        "Content-Type": "application/json",
    }
    response = api_request_with_retry("post", url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Unable to create role.  Status code: {response.status_code}")
    else:
        logging.info("Role successfully created")
        logging.info(response.text)

def create_descope_user(user):
    """
    Create a Descope user based on matched Auth0 user data.

    Args:
    - user (dict): A dictionary containing user details fetched from Auth0 API.
    """
    payload_data = {
        "loginId": user["email"],
        "email": user["email"],
        "verifiedEmail": user["email_verified"],
        "displayName": user["name"],
        "invite": False,
        "test": False,
        "picture": user["picture"],
    }
    payload = json.dumps(payload_data)
    url = "https://api.descope.com/v1/mgmt/user/create"
    headers = {
        "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
        "Content-Type": "application/json",
    }
    response = api_request_with_retry("post", url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Unable to create user.  Status code: {response.status_code}")
    else:
        logging.info("User successfully created")
        logging.info(response.text)

def add_user_to_descope_role(user,role):
    """
    Add a Descope user based on matched Auth0 user data.

    Args:
    - user (string): Login ID of the user you wish to add to role
    - role (string): The name of the role which you want to add the user to
    """
    payload_data = {
        "loginId": user,
        "roleNames": [role]
    }
    payload = json.dumps(payload_data)

    # Endpoint
    url = "https://api.descope.com/v1/mgmt/user/create"

    # Headers
    headers = {
        "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
        "Content-Type": "application/json",
    }
    # Make the POST request
    response = api_request_with_retry("post", url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Unable to add role to user.  Status code: {response.status_code}")
    else:
        logging.info("User role successfully added")
        logging.info(response.text)

def create_descope_tenant(organization):
    """
    Create a Descope create_descope_tenant based on matched Auth0 organization data.

    Args:
    - organization (dict): A dictionary containing organization details fetched from Auth0 API.
    """
    payload_data = {
        "name": organization["display_name"],
        "id": organization["id"]
    }
    payload = json.dumps(payload_data)

    # Endpoint
    url = "https://api.descope.com/v1/mgmt/tenant/create"

    # Headers
    headers = {
        "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
        "Content-Type": "application/json",
    }
    # Make the POST request
    response = api_request_with_retry("post", url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Unable to create tenant.  Status code: {response.status_code}")
    else:
        logging.info("Tenant successfully added")
        logging.info(response.text)

def add_descope_user_to_tenant(tenant, loginId):
    """
    Map a descope user to a tenant based on Auth0 data.

    Args:
    - tenant (string): The tenant ID of the tenant to associate the user.
    - loginId (string): the loginId of the user to associate to the tenant.
    """
    payload_data = {
        "loginId": loginId,
        "tenantId": tenant
    }
    payload = json.dumps(payload_data)
    print(payload)

    # Endpoint
    url = "https://api.descope.com/v1/mgmt/user/update/tenant/add"

    # Headers
    headers = {
        "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
        "Content-Type": "application/json",
    }
    # Make the POST request
    response = api_request_with_retry("post", url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Unable to add user to tenant.  Status code: {response.status_code}")
    else:
        logging.info("User successfully added to tenant")
        logging.info(response.text)

### End Descope Actions:

### Begin Process Functions

def process_users(api_response_users):
    """
    Process the list of users from Auth0 by mapping and creating them in Descope.

    Args:
    - api_response_users (list): A list of users fetched from Auth0 API.
    """
    for user in api_response_users:
        create_descope_user(user)

def process_roles(auth0_roles):
    """
    Process the Auth0 organizations - creating roles, permissions, and associating users

    Args:
    - auth0_roles (dict): Dictionary of roles fetched from Auth0
    """
    for role in auth0_roles:
        permissions = get_permissions_for_role(role["id"])
        create_descope_role_and_permissions(role, permissions)
        users = get_users_in_role(role["id"])
        for user in users:
            add_user_to_descope_role(user["email"],role["name"])

def process_auth0_organizations(auth0_organizations):
    """
    Process the Auth0 organizations - creating tenants and associating users

    Args:
    - auth0_organizations (dict): Dictionary of organizations fetched from Auth0
    """
    for organization in auth0_organizations:
        create_descope_tenant(organization)   
        org_members = fetch_auth0_organization_members(organization["id"])   
        for user in org_members:
            add_descope_user_to_tenant(organization["id"], user["email"])

### End Process Functions