"""
GrandmaGuard Authentication and User Management Module

This module provides a lightweight authentication system for the GrandmaGuard
security assessment platform. It implements basic user management with
Flask-Login integration for session management and access control to the
security dashboard and administrative interfaces.

Core Functionality:
- Simple user authentication with username/password credentials
- Flask-Login integration for session management and user persistence
- Environment-based password configuration for secure deployment
- In-memory user store suitable for single-admin deployments
- User session management with proper login/logout handling

Security Features:
- Environment variable-based password configuration
- Default development credentials with production override capability
- Session-based authentication preventing unauthorized access
- UserMixin integration providing standard authentication methods

Architecture Design:
This authentication system is designed for single-administrator deployments
where GrandmaGuard serves as a security analysis tool for a dedicated
security team. The simple architecture avoids complexity while providing
essential access control for sensitive security assessment data.

Deployment Considerations:
- Production deployments should set APP_ADMIN_PASSWORD environment variable
- Single admin user model suitable for most security assessment scenarios
- Can be extended to support multiple users or database-backed authentication
- Integration with enterprise authentication systems possible through extension

Usage:
The authentication system integrates seamlessly with Flask-Login to provide:
- Login page with credential validation
- Session persistence across browser sessions
- Access control decorators for protected routes
- Automatic logout and session cleanup

Classes:
    User: UserMixin-based user model for Flask-Login integration

Functions:
    get_user: User lookup function for Flask-Login user_loader callback

Author: GrandmaGuard Security Team
License: MIT
"""

# app/auth.py
import os
from flask_login import UserMixin, LoginManager


class User(UserMixin):
    """
    User model for GrandmaGuard authentication system.
    
    This class implements a simple user model using Flask-Login's UserMixin
    to provide standard authentication methods. It represents a single
    administrator user with basic credentials for accessing the GrandmaGuard
    security dashboard and administrative interfaces.
    
    The User class is designed for simplicity and single-admin deployments,
    providing essential authentication capabilities without database overhead.
    It integrates seamlessly with Flask-Login for session management and
    access control throughout the application.
    
    Attributes:
        id (str): Unique user identifier for session management
        username (str): Display name and login identifier
        password (str): User credential for authentication
    
    Methods:
        Inherits from UserMixin:
        - is_authenticated: Returns True if user is authenticated
        - is_active: Returns True if user account is active
        - is_anonymous: Returns False for authenticated users
        - get_id: Returns unique user identifier for session management
    
    Example:
        >>> user = User(id="1", username="admin", password="secure_password")
        >>> print(user.get_id())  # "1"
        >>> print(user.is_authenticated)  # True
    """
    
    def __init__(self, id, username, password):
        """
        Initialize a new User instance.
        
        Args:
            id (str): Unique identifier for the user
            username (str): Username for display and login
            password (str): User password for authentication
        """
        self.id = id
        self.username = username
        self.password = password


# In-memory user store for single-admin deployment model
admin_password = os.getenv("APP_ADMIN_PASSWORD", "default_password_for_dev")
users = {
    "1": User(id="1", username="admin", password=admin_password)
}


def get_user(user_id):
    """
    Retrieve user instance by user ID for Flask-Login integration.
    
    This function serves as the user_loader callback for Flask-Login,
    enabling the authentication system to retrieve user instances from
    session data. It looks up users from the in-memory user store and
    returns the corresponding User instance.
    
    The function is registered with Flask-Login's LoginManager to handle
    automatic user loading during request processing, enabling seamless
    session management and access control throughout the application.
    
    Args:
        user_id (str): Unique user identifier from the session
    
    Returns:
        User|None: User instance if found, None if user doesn't exist
    
    Example:
        >>> user = get_user("1")
        >>> if user:
        ...     print(f"Loaded user: {user.username}")
        Loaded user: admin
        
        >>> invalid_user = get_user("999")
        >>> print(invalid_user)  # None
    
    Note:
        This function is automatically called by Flask-Login during
        request processing and should not be called directly in
        application code.
    """
    return users.get(user_id)