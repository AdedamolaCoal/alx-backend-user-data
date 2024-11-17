#!/usr/bin/env python3
"""
API app for managing requests with authentication.
"""

from flask import Flask, jsonify, abort, request
from flask_cors import CORS
from os import getenv

app = Flask(__name__)
CORS(app)

# Initialize the auth variable
auth = None

# Set up the authentication based on AUTH_TYPE environment variable
AUTH_TYPE = getenv("AUTH_TYPE")
if AUTH_TYPE == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif AUTH_TYPE == "auth":
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
def before_request():
    """ Handle filtering of requests before processing """
    if auth is None:
        return

    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/', '/api/v1/forbidden/']
    if not auth.require_auth(request.path, excluded_paths):
        return

    if auth.authorization_header(request) is None:
        abort(401, description="Unauthorized")

    if auth.current_user(request) is None:
        abort(403, description="Forbidden")


@app.route('/api/v1/status/', methods=['GET'], strict_slashes=False)
def status():
    """ Returns the status of the API """
    return jsonify({"status": "OK"}), 200


@app.route('/api/v1/unauthorized/', methods=['GET'], strict_slashes=False)
def unauthorized():
    """ Test unauthorized error handler """
    abort(401, description="Unauthorized")


@app.route('/api/v1/forbidden/', methods=['GET'], strict_slashes=False)
def forbidden():
    """ Test forbidden error handler """
    abort(403, description="Forbidden")


@app.errorhandler(401)
def unauthorized_error(error):
    """ Error handler for 401 """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden_error(error):
    """ Error handler for 403 """
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
