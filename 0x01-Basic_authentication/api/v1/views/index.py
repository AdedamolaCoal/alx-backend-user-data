#!/usr/bin/env python3
"""
Index module to define routes for API endpoints,
including status check and unauthorized error test.
"""

from flask import Blueprint, abort, jsonify
from requests import Response


app_views = Blueprint('app_views', __name__, url_prefix='/api/v1')


@app_views.route('/api/v1/status', methods=['GET'])
def status():
    """
    Status route to check if the API is running.
    Returns:
        JSON response with status "OK".
    """
    return jsonify({"status": "OK"})


@app_views.route('/api/v1/unauthorized', methods=['GET'])
def unauthorized():
    """
    Route to test the custom 401 Unauthorized error handler.
    Raises:
        401 Unauthorized error to trigger error handler.
    """
    abort(401, Response('You are not authorized to view this page.'))


@app_views.route('/api/v1/forbidden', methods=['GET'])
def forbidden():
    """
    Route to test the custom 403 Forbidden error handler.
    Raises:
        403 Forbidden error to trigger error handler.
    """
    abort(403, Response('Forbidden for you.'))
