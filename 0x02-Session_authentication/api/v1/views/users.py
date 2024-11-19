#!/usr/bin/env python3
"""
user module for managing user routes.
"""

from flask import jsonify, abort, request
from models.user import User
from api.v1.views import app_views


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def get_user(user_id):
    """
    Retrieve a user by ID or the authenticated user (me).

    Args:
        user_id: id of user

    Return:
        User or 404
    """
    if user_id == "me":
        if request.current_user is None:
            abort(404)
        return jsonify(request.current_user.to_dict())

    user = User.get(user_id)
    if not user:
        abort(404)
    return jsonify(user.to_dict())
