#!/usr/bin/env python3
"""an unauthorized request to the
route /api/v1/status should
return a 401 status code
"""

from flask import Flask, jsonify
from api.v1.views import app_views
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.register_blueprint(app_views)


@app.errorhandler(401)
def unauthorized_error(error):
    """
    Custom handler for 401 Unauthorized errors.
    Returns:
        JSON response with an error message and a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401
