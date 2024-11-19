#!/usr/bin/env python3
"""
View module for handling user-related operations.

This module defines routes for retrieving
user information, including
the authenticated user and users by ID.
"""

from flask import jsonify, abort, request
from models.user import User
from api.v1.views import app_views


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def get_user(user_id):
    """
    Retrieve a user by their ID or
    the authenticated user (me).

    Args:
        user_id (str):
                The ID of the user to retrieve. If the ID is "me",
                it refers to the currently authenticated user.

    Returns:
        Response: A JSON response containing the user data.

    Raises:
        404: If the user ID does not exist or
        the user is not authenticated.
    """
    if user_id == "me":
        if request.current_user is None:
            abort(404)
        return jsonify(request.current_user.to_dict())

    user = User.get(user_id)
    if not user:
        abort(404)
    return jsonify(user.to_dict())
