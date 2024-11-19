#!/usr/bin/env python3
"""
Main file for testing the DB class.
"""

from db import DB

my_db = DB()

# Add users and print their IDs
user_1 = my_db.add_user("test@test.com", "SuperHashedPwd")
print(user_1.id)

user_2 = my_db.add_user("test1@test.com", "SuperHashedPwd1")
print(user_2.id)
