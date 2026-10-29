"""
------------------------------------------------------------
 Modul:    interface-partition/server_methods.py
 Projekt:  Secure IoT Gateway
------------------------------------------------------------
 Beschreibung:
    This module sets up the OPC UA methods for request 
    submission and user management. It includes methods
    for submitting requests, adding/removing users, updating
    user secrets, checking user existence, listing users,
    setting user roles, and getting user details.
    The POSIX message queue is used for inter-process
    communication with the intermediate VoR partition.

 Autor(en):
    - Heiko Schoon

 Maintainer:
    - Heiko Schoon <heiko.schoon@hs-emden-leer.de>

 Hinweis:
    Ongoing development.
------------------------------------------------------------
"""

import datetime
import uuid
import logging
import os
import re
import json
from asyncua import uamethod
from asyncua.ua import StatusCode, StatusCodes
from typing import Any

from user_manager import UserManagerTinyDB
from authorization_handler import AuthorizationHandler
from grpc_request_handler import send_request_as_grpc

_logger = logging.getLogger(__name__)

path = os.path.dirname(os.path.abspath(__file__))
parent_path = os.path.dirname(path)
#credentials_db_path = os.path.join(parent_path, "user_manager/credentials.db")
credentials_db_path = os.path.join(parent_path, "user_manager/credentials.json")
_user_manager = UserManagerTinyDB(credentials_db_path, max_connections=10)

"""try:
    if not os.getenv("ADMIN_PASSWORD"):
        raise ValueError("ADMIN_PASSWORD environment variable is not set.")
    _create_init_admin = _user_manager.create_user(username="admin", password=os.getenv("ADMIN_PASSWORD"))
except Exception as e:
    _logger.error(f"Error creating initial Admin user: {e}")"""

from pathlib import Path
path = Path(__file__).resolve().parent
parent_path = path.parent
casbin_model_path_res = Path(parent_path / "authorization_handler" / "rbac_with_resource_roles_model.conf")
casbin_policy_path_res = Path(parent_path / "authorization_handler" / "rbac_test_with_impacts.csv") 


# Log resolved Casbin paths for debugging
_logger.debug(f"Casbin model path: {casbin_model_path_res}")
_logger.debug(f"Casbin policy path: {casbin_policy_path_res}")
_rbac_authorization_handler = AuthorizationHandler(str(casbin_model_path_res), str(casbin_policy_path_res))

# When True, a failed authorization response tells the caller which actions
# the issuer IS allowed to perform on the requested resource. Set to False
# in environments where leaking allowed actions is a security concern.
RETURN_ALLOWED_IMPACTS_ON_AUTHZ_FAILURE: bool = os.getenv(
    "VOR1_RETURN_ALLOWED_IMPACTS_ON_AUTHZ_FAILURE", "true"
).strip().lower() in ("1", "true", "yes", "on")


def get_allowed_actions_for_user(issuer_id: str, parameters: str) -> list[str]:
    """
    Return the sorted list of impacts the given issuer is permitted to request
    for the given parameter, according to the Casbin policy.
    Used to populate the authorization-failure message with actionable guidance.
    """
    allowed: list[str] = []
    for policy in _rbac_authorization_handler.enforcer.get_policy():
        if len(policy) < 3:
            continue
        _, policy_resource, policy_action = policy[:3]
        if policy_resource != parameters:
            continue
        if _rbac_authorization_handler.verify_authorization(
            issuer_id, parameter_name=parameters, action=policy_action
        ):
            allowed.append(policy_action)
    return sorted(set(allowed))


#@uamethod  #TODO: test...
# TODO: Update method parameters according the project/NOA-standard requirements and yuanchens additional developments
# TODO: Implement additional UserManagement 
#def submit_request(parent: Any, issuer_id: str, credentials: str, issuer_characteristics: list[str], timestamp: str, 
#                  #description: list[str], impact: list[str], parameters: str,
#                  description: list[str], impact: str, parameters: str,
#                  modification: str, priority: int) -> tuple[str, str, str]:
async def submit_request(
    parent,
    issuer_id: str,
    credentials: str,
    issuer_characteristics: list[str],
    timestamp: str,
    description: list[str],
    impact: str,
    parameters: str,
    modification: str,
    priority: int,
    *,
    grpc_config,
) -> tuple[str, str, str]:
    """
    OPC UA method to handle a request submission.

    Args:
        parent: The parent node in the OPC UA server.
        issuer_id: The unique identifier of the request issuer.
        credentials: The credentials of the request issuer.
        timestamp: The timestamp of the request.
        description: Human readable description of the request.
        impact: Impacts and benefits of the request.
        parameters: Parameters affected by the request.
        modification: Machine readable description of the requested changes.
        priority: The priority of the request.

    Returns:
        tuple: A tuple containing the request ID, server timestamp, and a notification message.
    """
    request_id = str(uuid.uuid4())
    server_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Format Request using JSON
    request_dict = {
        "issuer_id": issuer_id,
        #"credentials": Credentials are being removed before sending the request to the VoR partition for security reasons
        "issuer_characteristics": {},
        "timestamp": str(timestamp),
        "description": {},
        "impact": impact,
        "parameters": parameters,
        "modification": modification,
        "prio": priority,
        "request_id": request_id
    }
    # list.index() returns the position of the FIRST occurrence, so duplicate
    # non-empty strings would map to the same key and silently overwrite each
    # other. enumerate() always uses the iteration position, which is unique.
    for idx, i in enumerate(issuer_characteristics):
        if i:
            request_dict["issuer_characteristics"][f"issuer_characteristics_{idx}"] = i

    for idx, descr in enumerate(description):
        if descr:
            request_dict["description"][f"description_{idx}"] = descr
    _logger.info(f"Request: {request_dict}")

    # 0) Validate and normalise the modification field.
    #    Strip outer parentheses that some clients send, e.g. "(5)" -> "5".
    if isinstance(modification, str) and modification.startswith("(") and modification.endswith(")"):
        modification = modification[1:-1]
    #    Normalise Python/OPC UA boolean variants to lowercase strings.
    if isinstance(modification, bool):
        modification = str(modification).lower()
    elif isinstance(modification, str) and modification.lower() in ("true", "false"):
        modification = modification.lower()
    #    Reject anything that is not a number (optionally with %), a percentage, or a boolean.
    _mod_pattern = r"^(?:-?\d+(?:\.\d+)?%?|true|false)$"
    if not re.fullmatch(_mod_pattern, str(modification)):
        _logger.warning(f"Invalid modification value from {issuer_id}: {modification!r}")
        return request_id, server_timestamp, "Invalid input for modification."
    #    Store the normalised value in the request dict.
    request_dict["modification"] = modification

    # 1) Authenticate the request issuer
    if not _user_manager.verify_credentials(username=issuer_id, password=credentials):
        _logger.error(f"Authentication failed for {issuer_id}")
        return request_id, server_timestamp, f"Authentication failed for {issuer_id}"

    # 2) Authorize the request issuer
    # TODO: Create first a list of parameters and actions to be authorized .csv file and .conf file
    # TODO: Create documentation of parameters/actions, users/credentials, roles, and policies (initial users/credentials e.g., Admin etc.)
    if not _rbac_authorization_handler.verify_authorization(issuer_id, parameter_name=parameters, action=f'"{impact}"'):
        _logger.error(f"Authorization failed for {issuer_id} with parameters {parameters} and action {impact}")
        if RETURN_ALLOWED_IMPACTS_ON_AUTHZ_FAILURE: #BUG: Sec vuln, REMOVE
            allowed = get_allowed_actions_for_user(issuer_id, parameters)
            return (
                request_id,
                server_timestamp,
                f"Request authorization failed: {issuer_id}. "
                f"Allowed actions for '{parameters}': {json.dumps(allowed, ensure_ascii=False)}",
            )
        return request_id, server_timestamp, f"Request authorization failed: {issuer_id}"
    
    # 3) Submit the request to the intermediate VoR partition
    # Setup POSIX message queue for ipc with the intermediate VoR partition
    try:
        #send_request_as_grpc(request=request_dict)
        send_request_as_grpc(request=request_dict, config=grpc_config)
        _logger.info(f"Request with priority {priority} at {server_timestamp} received and forwared.")
    except Exception as e:
        _logger.error(f"Error submit request method: {e}")
        return request_id, server_timestamp, f"Error: {str(e)}"

    return request_id, server_timestamp, f"Submission received"

@uamethod
def add_user(parent: Any, admin_id: str, admin_secret: str, 
             user_id: str, secret: str) -> tuple[StatusCode, str]: 
    # TODO: add_user / add_user_to_role methods, add new rules directly via method and retain the new config file!, give user two roles? @casbin, methoden kombinieren
    """
    Add a new user to the system.
    
    Args:
        parent: The parent node in the OPC UA server.
        admin_id: Administrator identifier.
        admin_secret: Administrator credentials.
        user_id: New user identifier.
        secret: Password for the new user.
        
    Returns:
        tuple: Status code and result message.
    """
    if not _user_manager.verify_credentials(username=admin_id, password=admin_secret):
        return StatusCode(StatusCodes.BadUserAccessDenied), f"Authentication failed for admin {admin_id}."
    if not _rbac_authorization_handler.check_admin_role(admin_id):
        return StatusCode(StatusCodes.BadUserAccessDenied), f"Admin role required for adding users."
    if  not _rbac_authorization_handler.check_user_exists(user_id):
        return StatusCode(StatusCodes.BadUserAccessDenied), f"User {user_id} is not part of RBAC policy."
    try:
        res = _user_manager.create_user(username=user_id, password=secret)
        #user_exists_rbac = _rbac_authorization_handler.check_user_exists(user_id)
        #_logger.error(f"User exists in RBAC: {user_exists_rbac}")
        if res:
            return StatusCode(StatusCodes.Good), f"User {user_id} added successfully and already exists within RBAC."
        # if res and not user_exists_rbac:
        #     # TODO: Add user to RBAC
        #     #res_rbac = _rbac_authorization_handler.add_user(user_id)
        #     res_rbac = False
        #     if res_rbac:
        #         return StatusCode(StatusCodes.Good), f"User {user_id} added successfully to UserManager and RBAC."
        #     else:
        #         return StatusCode(StatusCodes.BadUnexpectedError), f"NOT_IMPLEMENTED: Failed to add user {user_id} to RBAC."
        else:
            return StatusCode(StatusCodes.BadUnexpectedError), f"Failed to add user {user_id}."
    except Exception as e:
        _logger.error(f"Error adding user: {e}")
        return StatusCode(StatusCodes.BadInternalError), f"Error: {str(e)}"

@uamethod
def remove_user(parent: Any, admin_id: str, admin_secret: str, 
                user_id: str) -> tuple[StatusCode, str]:
    """
    Remove a user from the system.
    
    Args:
        parent: The parent node in the OPC UA server.
        admin_id: Administrator identifier.
        admin_secret: Administrator credentials.
        user_id: User to remove.
        
    Returns:
        tuple: Status code and result message.
    """
    try:
        # Check if User is really Admin (Roleset, Authorization)!
        if not _user_manager.verify_credentials(username=admin_id, password=admin_secret):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Authentication failed for admin {admin_id}."
        if not _rbac_authorization_handler.check_admin_role(admin_id):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Admin role required for user deletion."
        
        # Check if user is last admin and prevent deletion
        if len(_rbac_authorization_handler.get_all_admins()) == 1 and _rbac_authorization_handler.check_admin_role(user_id):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Cannot delete last admin user."

        # Get the user record first to get their ID
        res, user_record = _user_manager.retrieve_user(user_id)
        if not res or user_record is None:
            return StatusCode(StatusCodes.BadNoMatch), f"User {user_id} not found."
        
        # Check if User exists in the RBAC policy
        # TODO: How to add new users to the RBAC policy?
        # if not _rbac_authorization_handler.check_user_exists(user_id):
        #     return StatusCode(StatusCodes.BadNoMatch), f"User {user_id} not found in RBAC policy."
        
        # Delete using the user's ID from the record
        user_db_id = user_record[0]  # First field is the ID
        res = _user_manager.delete_user(user_db_id)
        res_rbac = _rbac_authorization_handler.remove_user(user_id)
        if res and res_rbac:
            return StatusCode(StatusCodes.Good), f"User {user_id} deleted successfully."
        else:
            return StatusCode(StatusCodes.BadNoMatch), f"User {user_id} not found or could not be deleted."
    except Exception as e:
        _logger.error(f"Error removing user: {e}")
        return StatusCode(StatusCodes.BadInternalError), f"Error: {str(e)}"

@uamethod
def update_user_secret(parent: Any, user_id: str, secret: str, 
                      new_secret: str) -> tuple[StatusCode, str]:
    """
    Update a user's password.
    
    Args:
        parent: The parent node in the OPC UA server.
        user_id: User identifier.
        secret: Current password.
        new_secret: New password.
        
    Returns:
        tuple: Status code and result message.
    """
    try:
        if not _user_manager.verify_credentials(username=user_id, password=secret):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Authentication failed for user {user_id}."
        
        res = _user_manager.update_user(username=user_id, old_password=secret, new_password=new_secret)
        if res:
            return StatusCode(StatusCodes.Good), f"User {user_id} secret updated successfully."
        else:
            return StatusCode(StatusCodes.BadUnexpectedError), f"Failed to update secret for user {user_id}."
    except Exception as e:
        _logger.error(f"Error updating user secret: {e}")
        return StatusCode(StatusCodes.BadInternalError), f"Error: {str(e)}"

@uamethod
def check_user_exists(parent: Any, user_id: str) -> tuple[StatusCode, bool, str]:
    """
    Check if a user exists in the system.
    
    Args:
        parent: The parent node in the OPC UA server.
        user_id: User identifier to check.
        
    Returns:
        tuple: Status code, existence flag, and result message.
    """
    try:
        res, user_record = _user_manager.retrieve_user(user_id)
        # If retrieve_user returns success and a record, user exists
        exists = res and user_record is not None
        if exists:
            return StatusCode(StatusCodes.Good), True, f"User {user_id} exists."
        else:
            return StatusCode(StatusCodes.Good), False, f"User {user_id} does not exist."
    except Exception as e:
        _logger.error(f"Error checking user existence: {e}")
        return StatusCode(StatusCodes.BadInternalError), False, f"Error: {str(e)}"
    
@uamethod
def list_users(parent: Any, admin_id: str, admin_secret: str) -> tuple[StatusCode, list[str], str]:
    """
    List all users in the system.
    
    Args:
        parent: The parent node in the OPC UA server.
        admin_id: Administrator identifier.
        admin_secret: Administrator credentials.
        
    Returns:
        tuple: Status code, list of usernames, and result message.
    """
    try:
        if not _user_manager.verify_credentials(username=admin_id, password=admin_secret):
            return StatusCode(StatusCodes.BadUserAccessDenied), [""], f"Authentication failed for admin {admin_id}."
        
        if not _rbac_authorization_handler.check_admin_role(admin_id):
            return StatusCode(StatusCodes.BadUserAccessDenied), [""], f"Admin role required for user listing."

        # UserManagerTinyDB.get_all_users() queries the TinyDB credentials table
        # directly and returns a list[str] of usernames.
        # The old code called _get_connection()/_return_connection() which belonged
        # to a previous SQLite-backed implementation and no longer exists.
        users = _user_manager.get_all_users() 
        return StatusCode(StatusCodes.Good), users, f"Successfully retrieved {len(users)} users."
    
    except Exception as e:
        _logger.error(f"Error listing users: {e}")
        return StatusCode(StatusCodes.BadInternalError), [""], f"Error: {str(e)}"
    
@uamethod
def set_user_role(parent: Any, admin_id: str, admin_secret: str, 
                 user_id: str, role: str) -> tuple[StatusCode, str]:
    """
    Set a user's role in the system.
    
    Args:
        parent: The parent node in the OPC UA server.
        admin_id: Administrator identifier.
        admin_secret: Administrator credentials.
        user_id: User to modify.
        role: New role to assign.
        
    Returns:
        tuple: Status code and result message.
    """
    # TODO: Implementation requires active updating of the casbin-policy.csv file and potentially the model.conf file
    try:
        if not _user_manager.verify_credentials(username=admin_id, password=admin_secret):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Authentication failed for admin {admin_id}."
        
        if not _rbac_authorization_handler.check_admin_role(admin_id):
            return StatusCode(StatusCodes.BadUserAccessDenied), f"Admin role required for user role management."

        # The current UserManager doesn't have role management
        # This would need to be implemented in the UserManager class
        # For now, return a message indicating this isn't implemented
        return StatusCode(StatusCodes.BadNotImplemented), f"Role management is not implemented yet."
    except Exception as e:
        _logger.error(f"Error setting user role: {e}")
        return StatusCode(StatusCodes.BadInternalError), f"Error: {str(e)}"
    
@uamethod
def get_user_details(parent: Any, admin_id: str, admin_secret: str, 
                    user_id: str) -> tuple[StatusCode, list[str], str]:
    """
    Get detailed information about a user.
    
    Args:
        parent: The parent node in the OPC UA server.
        admin_id: Administrator identifier.
        admin_secret: Administrator credentials.
        user_id: User to retrieve details for.
        
    Returns:
        tuple: Status code, list of user details, and result message.
    """
    try:
        if not _user_manager.verify_credentials(username=admin_id, password=admin_secret):
            return StatusCode(StatusCodes.BadUserAccessDenied), [""], f"Authentication failed for admin {admin_id}."
        
        if not _rbac_authorization_handler.check_admin_role(admin_id):
            return StatusCode(StatusCodes.BadUserAccessDenied), [""], f"Admin role required for user detail extraction."
        # TODO: Add user role details from _rbac_authorization_handler
        # Retrieve user details
        res, user_record = _user_manager.retrieve_user(user_id)
        if not res or user_record is None:
            return StatusCode(StatusCodes.BadNoMatch), [""], f"User {user_id} not found."
        
        # Format the user details as strings in a list
        # Format: "field_name:value"
        # Skipping the password hash for security
        details = []
        if user_record:
            fields = ["id", "username", "role", "created_at", "last_login"] 
            # Add available fields from the user record
            details.append(f"id:{user_record[0]}")
            details.append(f"username:{user_record[1]}")
            # Don't include password hash (index 2) or salt (index 3)
            
            # Add any extra fields if they exist in your schema
            # Currently the schema only has id, username, password, salt
            
        return StatusCode(StatusCodes.Good), details, f"Successfully retrieved details for user {user_id}."
    except Exception as e:
        _logger.error(f"Error getting user details: {e}")
        return StatusCode(StatusCodes.BadInternalError), [""], f"Error: {str(e)}"