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

def is_valid(hashed_password: bytes, password: str) -> bytes:
  """is valid function
  
  Args:
      hashed_password (bytes): hashed password to check
      password (str): password to check
      
  Returns: 
      bytes: hashed password
  """
  is_valid = bcrypt.checkpw(password.encode('utf-8'), hashed_password)
  return is_valid
