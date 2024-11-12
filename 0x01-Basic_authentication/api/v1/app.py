#!/usr/bin/env python3
"""
API app for managing requests with authentication.
"""

from flask import Flask, jsonify, abort, request
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Initialize the auth variable
auth = None

# Set up the authentication based on AUTH_TYPE environment variable
AUTH_TYPE = os.getenv("AUTH_TYPE")
if AUTH_TYPE == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()


@app.errorhandler(401)
def unauthorized_error(error):
    """Handles 401 Unauthorized error."""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden_error(error):
    """Handles 403 Forbidden error."""
    return jsonify({"error": "Forbidden"}), 403

# Define the before_request handler for request filtering


@app.before_request
def before_request_handler():
    """Request filtering for authentication."""
    if auth is None:
        return

    # Define the paths that do not require authentication
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/', '/api/v1/forbidden/']

    # Check if the path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Check for Authorization header
    if auth.authorization_header(request) is None:
        abort(401)

    # Check for current user
    if auth.current_user(request) is None:
        abort(403)

# Example endpoint


@app.route('/api/v1/status/', methods=['GET'])
def status():
    """Status route to check API status."""
    return jsonify({"status": "OK"})

# Unauthorized route for testing


@app.route('/api/v1/unauthorized/', methods=['GET'])
def unauthorized():
    """Route that raises 401 Unauthorized error."""
    abort(401)

# Forbidden route for testing


@app.route('/api/v1/forbidden/', methods=['GET'])
def forbidden():
    """Route that raises 403 Forbidden error."""
    abort(403)
