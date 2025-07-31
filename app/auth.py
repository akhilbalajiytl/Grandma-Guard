# app/auth.py
import os
from flask_login import UserMixin, LoginManager

# 1. Define the User class here. It's not a database model.
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# 2. Define the in-memory user store here.
admin_password = os.getenv("APP_ADMIN_PASSWORD", "default_password_for_dev")
users = {
    "1": User(id="1", username="admin", password=admin_password)
}

# 3. Define the user_loader function. It will be registered in __init__.py
def get_user(user_id):
    """This function is used by Flask-Login to get a user from a user_id."""
    return users.get(user_id)