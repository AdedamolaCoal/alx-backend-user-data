#!/usr/bin/env python3
"""
Flask app for user registration.
"""
from flask import Flask, jsonify, request
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5001")
