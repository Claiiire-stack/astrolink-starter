"""
Satellite pages: list the fleet, and (next step) send commands.
"""

from flask import Blueprint, render_template
from flask_login import login_required
from app.models import Satellite

commands_bp = Blueprint("commands", __name__)


@commands_bp.route("/satellites")
@login_required
def list_satellites():
    satellites = Satellite.query.order_by(Satellite.name).all()
    return render_template("satellites.html", satellites=satellites)