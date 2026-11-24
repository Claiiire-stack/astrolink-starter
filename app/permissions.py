"""
Permission rules: which role may do what.

Every permission check in the app goes through this file, so there is
one place to review and explain.
"""

from functools import wraps
from flask import abort
from flask_login import current_user
from app.simulator import COMMANDS

# Higher number = more powerful. A role not listed here gets nothing.
ROLE_LEVEL = {
    "intern": 0,
    "operator": 1,
    "senior_operator": 2,
    "admin": 3,
}

# The lowest role allowed to REQUEST a command of each risk level.
MIN_ROLE_FOR_RISK = {
    "low": "operator",
    "medium": "senior_operator",
    "high": "senior_operator",
    "critical": "admin",
}

# Risk levels that also need a second person to approve (built in a later step).
NEEDS_APPROVAL = {"high", "critical"}


def role_level(role):
    """Turn a role name into a number. Unknown roles get -1 (deny by default)."""
    return ROLE_LEVEL.get(role, -1)


def can_send(user, command_type):
    """True if this user's role may request this command."""
    command = COMMANDS.get(command_type)
    if command is None:
        return False
    needed_role = MIN_ROLE_FOR_RISK[command["risk"]]
    return role_level(user.role) >= role_level(needed_role)


def needs_approval(command_type):
    """True if this command must be approved by a second person."""
    command = COMMANDS.get(command_type)
    return command is not None and command["risk"] in NEEDS_APPROVAL


def role_required(minimum_role):
    """
    Protect a whole page. Use it under @login_required:

        @bp.route("/admin")
        @login_required
        @role_required("admin")
        def admin_page(): ...
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if role_level(current_user.role) < role_level(minimum_role):
                abort(403)  # 403 = "you are not allowed"
            return view(*args, **kwargs)
        return wrapper
    return decorator