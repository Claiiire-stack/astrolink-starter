"""
Satellite pages: list the fleet and send commands.

Security rules in this file:
  1. Permission is checked on the SERVER for every command (never trust the form).
  2. Every attempt is logged: executed, failed, denied, or pending approval.
  3. High-risk commands are queued for a second person instead of running.
"""

import re
from flask import Blueprint, render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from app.models import db, Satellite, CommandLog
from app.simulator import COMMANDS, execute_command
from app.permissions import can_send, needs_approval

commands_bp = Blueprint("commands", __name__)


def log_command(satellite, command_type, parameter, status, description):
    """Save one row in the command log: who, what, which satellite, outcome."""
    db.session.add(CommandLog(
        satellite_id=satellite.id,
        user_id=current_user.id,
        command_type=(command_type or "unknown")[:50],
        parameter=(parameter or "")[:100],
        description=description,
        status=status,
        ip_address=request.remote_addr,
    ))
    db.session.commit()


def check_parameter(command_type, parameter):
    """Extra safety checks. Returns an error message, or None if fine."""
    if command_type == "firmware_update":
        if not re.fullmatch(r"\d+\.\d+\.\d+", parameter):
            return "Firmware version must look like 3.2.2"
    return None


@commands_bp.route("/satellites")
@login_required
def list_satellites():
    satellites = Satellite.query.order_by(Satellite.name).all()
    can_command = can_send(current_user, "ping")  # ping is the lowest-level command
    return render_template("satellites.html", satellites=satellites, can_command=can_command)


@commands_bp.route("/satellites/<int:satellite_id>/command", methods=["GET", "POST"])
@login_required
def send_command(satellite_id):
    satellite = db.session.get(Satellite, satellite_id)
    if satellite is None:
        abort(404)

    # Only the commands this user's role is allowed to send.
    allowed = {key: cmd for key, cmd in COMMANDS.items() if can_send(current_user, key)}

    if request.method == "POST":
        command_type = request.form.get("command_type", "")
        parameter = request.form.get("parameter", "").strip()

        # 1. Permission check, on the server, every single time.
        if not can_send(current_user, command_type):
            log_command(satellite, command_type, parameter, "denied",
                        f"{current_user.username} ({current_user.role}) was refused "
                        f"{command_type} on {satellite.name}")
            abort(403)

        # 2. Extra safety check on the value.
        problem = check_parameter(command_type, parameter)
        if problem:
            flash(problem, "danger")
            return redirect(url_for("commands.send_command", satellite_id=satellite.id))

        command = COMMANDS[command_type]

        # 3. Anything above low risk needs a confirmation screen first.
        if command["risk"] != "low" and request.form.get("confirmed") != "yes":
            return render_template("send_command.html", satellite=satellite,
                                   confirm=command, command_type=command_type,
                                   parameter=parameter)

        # 4. High and critical commands wait for a second person (built in a later step).
        if needs_approval(command_type):
            log_command(satellite, command_type, parameter, "pending_approval",
                        f"{command['label']} on {satellite.name} is waiting for a second person to approve")
            flash("That command needs a second person to approve it. It has been queued.", "success")
            return redirect(url_for("commands.list_satellites"))

        # 5. Run it, and log what happened.
        try:
            result = execute_command(satellite, command_type, parameter)
        except ValueError as error:
            db.session.rollback()
            log_command(satellite, command_type, parameter, "failed", str(error))
            flash(str(error), "danger")
            return redirect(url_for("commands.send_command", satellite_id=satellite.id))

        log_command(satellite, command_type, parameter, "executed", result)
        flash(result, "success")
        return redirect(url_for("commands.list_satellites"))

    # GET: show the form. Roles that can send nothing (interns) get "forbidden".
    if not allowed:
        abort(403)
    return render_template("send_command.html", satellite=satellite, allowed=allowed)