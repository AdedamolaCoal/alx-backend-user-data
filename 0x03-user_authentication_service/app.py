#!/usr/bin/env python3
"""
Flask app for user registration.
"""
from flask import Flask, request, jsonify, abort, make_response, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/users", methods=["POST"])
def users():
    """
    POST /users endpoint to register a new user.

    Expects:
        - email: User's email as form data.
        - password: User's password as form data.

    Responses:
        - 200: User successfully created.
        - 400: User already exists.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify(
            {"message": "email and password required"}), 400

    try:
        user = AUTH.register_user(email, password)
        return jsonify(
            {"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify(
            {"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """
    POST /sessions route to log in a user.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    # Validate login credentials
    if not AUTH.valid_login(email, password):
        abort(401)

    # Create a session for the user
    session_id = AUTH.create_session(email)
    if not session_id:
        abort(401)

    # Set the session_id cookie and return response
    response = make_response(jsonify({"email": email, "message": "logged in"}))
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'])
def logout():
    """
    Handles DELETE /sessions to log out the user.
    - Expects 'session_id' as a cookie.
    - If session is valid, destroys the session and redirects to '/'.
    - If no valid session is found, returns a 403 status code.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile():
    """
    Profile endpoint to retrieve the user's email based on the session ID.
    - Reads the `session_id` cookie from the request.
    - Uses `AUTH.get_user_from_session_id` to fetch the user.
    - If a valid user is found, responds with a 200 status and user's email.
    - If the session is invalid or user not found, responds with a 403 status.
    """
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """
    Generate a reset password token for a given email.
    - Expects "email" field in the form data.
    - If the email is not registered, respond with a 403 HTTP status.
    - Otherwise, generate a reset token and respond with:
      {"email": "<user email>", "reset_token": "<reset token>"}
    """
    email = request.form.get('email')
    if not email:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5001")
