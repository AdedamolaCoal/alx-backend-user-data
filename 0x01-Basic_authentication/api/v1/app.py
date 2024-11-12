#!/usr/bin/env python3
"""an unauthorized request to the
route /api/v1/status should
return a 401 status code
"""

from flask import Flask, jsonify, request, abort
from api.v1.views import app_views
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app)


auth = None

AUTH_TYPE = os.getenv("AUTH_TYPE")
if AUTH_TYPE == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif AUTH_TYPE == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()


@app.errorhandler(401)
def unauthorized_error(error):
    """
    Custom handler for 401 Unauthorized errors.
    Returns:
        JSON response with an error message and a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden_error(error):
  """
  Custom handler for 403 Forbidden errors.

  Returns:
      JSON response with an error message and a 403 status code.
  """
  return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request_handler():
    """Request filtering for authentication."""
    if auth is None:
        return

    # Define the paths that do not require authentication
    excluded_paths = ['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']
    
    # Check if the path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Check for Authorization header
    if auth.authorization_header(request) is None:
        abort(401)

    # Check for current user
    if auth.current_user(request) is None:
        abort(403)
