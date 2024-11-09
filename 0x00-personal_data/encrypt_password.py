#!/usr/bin/env python3
"""encrypt_password module"""

import bcrypt

def hash_password(password: str) -> bytes:
  """hash_password function
  
  Args:
      password (str): password to hash
  
  Returns:
      bytes: hashed password
  """
  return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
